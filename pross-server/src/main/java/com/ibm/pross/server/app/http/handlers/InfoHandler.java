package com.ibm.pross.server.app.http.handlers;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentMap;

import org.apache.commons.codec.binary.Hex;

import com.ibm.pross.common.CommonConfiguration;
import com.ibm.pross.server.app.avpss.ApvssShareholder;
import com.ibm.pross.server.app.http.HttpRequestProcessor;
import com.ibm.pross.server.app.http.HttpStatusCode;
import com.ibm.pross.server.configuration.permissions.AccessEnforcement;
import com.ibm.pross.server.configuration.permissions.ClientPermissions.Permissions;
import com.ibm.pross.server.configuration.permissions.exceptions.BadRequestException;
import com.ibm.pross.server.configuration.permissions.exceptions.NotFoundException;
import com.ibm.pross.server.configuration.permissions.exceptions.UnauthorizedException;
import com.sun.net.httpserver.HttpExchange;

import bftsmart.reconfiguration.util.sharedconfig.KeyLoader;
import bftsmart.reconfiguration.util.sharedconfig.ServerConfiguration;

/**
 * This handler returns information about a secret. Client's must have a
 * specific authorization to be able to invoke this method. If the secret is not
 * found a 404 is returned. If the client is not authorized a 403 is returned.
 * 
 * <pre>
 * Information about the secret includes:
 * - The name of the secret
 * - The public key of the secret
 * - The current epoch id of the secret (first is zero)
 * - The shareholder public verification keys of the secret
 * - The Feldman co-efficients of the secret
 * - The time the secret was first generated/stored by this server
 * - The id of the client who performed the creation or generation of the secret
 * - The time the secret was last proactively refreshed by this server
 * - The next scheduled time for this server to begin a proactive refresh
 * - The number of shares and the reconstruction threshold of the secret
 * - The prime field of the shamir sharing of the secret
 * - The elliptic curve group for exponentiation operations
 * </pre>
 */
@SuppressWarnings("restriction")
public class InfoHandler extends AuthenticatedClientRequestHandler {

	public static final Permissions REQUEST_PERMISSION = Permissions.INFO;

	// Query name
	public static final String SECRET_NAME_FIELD = "secretName";

	// Fields
	private final AccessEnforcement accessEnforcement;
	private final ServerConfiguration serverConfig;
	private final ConcurrentMap<String, ApvssShareholder> shareholders;

	public InfoHandler(final KeyLoader clientKeys, final AccessEnforcement accessEnforcement, final ServerConfiguration serverConfig,
			final ConcurrentMap<String, ApvssShareholder> shareholders) {
		super(clientKeys);
		this.shareholders = shareholders;
		this.serverConfig = serverConfig;
		this.accessEnforcement = accessEnforcement;
	}

	@Override
	public void authenticatedClientHandle(final HttpExchange exchange, final Integer clientId)
			throws IOException, UnauthorizedException, NotFoundException, BadRequestException {

		// Extract secret name from request
		final String queryString = exchange.getRequestURI().getQuery();
		final Map<String, List<String>> params = HttpRequestProcessor.parseQueryString(queryString);
		final List<String> secretNames = params.get(SECRET_NAME_FIELD);
		if (secretNames == null || secretNames.size() != 1) {
			throw new BadRequestException();
		}
		final String secretName = secretNames.get(0);

		// Perform authentication
		accessEnforcement.enforceAccess(clientId, secretName, REQUEST_PERMISSION);

		// Do processing
		final ApvssShareholder shareholder = this.shareholders.get(secretName);
		if (shareholder == null) {
			throw new NotFoundException();
		}

		// Create response
		final String response = getSecretInfo(shareholder, secretName, serverConfig);
		final byte[] binaryResponse = response.getBytes(StandardCharsets.UTF_8);

		// Write headers
		//exchange.getResponseHeaders().add("Strict-Transport-Security", "max-age=300; includeSubdomains");
		exchange.sendResponseHeaders(HttpStatusCode.SUCCESS, binaryResponse.length);
		
		// Write response
		try (final OutputStream os = exchange.getResponseBody();) {
			os.write(binaryResponse);
		}
	}

	private static String getSecretInfo(final ApvssShareholder shareholder, final String secretName,
			final ServerConfiguration serverConfig) {

		// This server
		final int serverIndex = shareholder.getIndex();
		final InetSocketAddress thisServerAddress = serverConfig.getServerAddresses().get(serverIndex - 1);
		final String ourIp = thisServerAddress.getHostString();
		final int ourPort = HttpRequestProcessor.BASE_HTTP_PORT + serverIndex;

		// Create response
		final StringBuilder stringBuilder = new StringBuilder();
		stringBuilder.append("<html>\n");
		stringBuilder.append("<head>\n");
		stringBuilder.append("<meta http-equiv=\"refresh\" content=\"10\">\n");
		stringBuilder.append("</head>\n");
		stringBuilder.append("<body>\n");
		stringBuilder.append("<tt>\n");

		// Shareholder information
		stringBuilder.append("This is <a href=\"/\">shareholder #" + serverIndex + "</a>"
				+ " running <a href=\"https://github.com/jasonkresch/protect\">PROTECT</a>,"
				+ " a <b>P</b>latform for <b>Ro</b>bust <b>T</b>hr<b>e</b>shold <b>C</b>ryp<b>t</b>ography.\n");
		stringBuilder.append("<p/>\n");

		// Secret Info
		stringBuilder.append("<b>Information for \"" + secretName + "\":</b><br/>\n");
		final int n = shareholder.getN();
		final int k = shareholder.getK();
		if (shareholder.getSecretPublicKey() == null) {
			final String linkUrl = "https://" + ourIp + ":" + ourPort + "/generate?secretName=" + secretName;
			stringBuilder.append("Secret not yet established. (<a href=\"" + linkUrl + "\">Perform DKG</a>)<br/>\n");
		} else {
			stringBuilder.append("sharing_type             =  " + shareholder.getSharingType() + "<br/>\n");
			stringBuilder.append("g^{s}                    =  " + shareholder.getSecretPublicKey() + "<br/>\n");
			stringBuilder.append("number_of_shares         =  " + shareholder.getN() + "<br/>\n");
			stringBuilder.append("reconstruction_threshold =  " + shareholder.getK() + "<br/>\n");
			stringBuilder.append("creation_time            =  " + shareholder.getCreationTime() + "<br/>\n");
			stringBuilder.append("<p/>\n");

			// Print Epoch information
			stringBuilder.append("<b>Epoch:</b><br/>\n");
			stringBuilder.append("epoch_number      =  " + shareholder.getEpoch() + "<br/>\n");
			stringBuilder.append("last_refresh_time =  " + shareholder.getLastRefreshTime() + "<br/>\n");
			stringBuilder.append("refresh_frequency =  " + shareholder.getRefreshFrequency() + " seconds<br/>\n");
			stringBuilder.append("<p/>\n");

			// Print Field Information
			stringBuilder.append("<b>Field Information:</b><br/>\n");
			stringBuilder.append("prime_modulus    =  " + CommonConfiguration.CURVE.getR() + "<br/>\n");
			stringBuilder.append("curve_oid        =  " + CommonConfiguration.CURVE.getOid() + " ("
					+ CommonConfiguration.CURVE.getName() + ")<br/>\n");
			stringBuilder.append("<p/>\n");

			// Print share verification keys
			stringBuilder.append("<b>Share Verification Keys:</b><br/>\n");
			for (int i = 1; i <= n; i++) {
				stringBuilder.append("g^{s_" + i + "} =  " + shareholder.getSharePublicKey(i) + "<br/>\n");
			}
			stringBuilder.append("<p/>\n");

			// Print Feldman Coefficients
			stringBuilder.append("<b>Feldman Coefficients:</b><br/>\n");
			for (int i = 0; i < k; i++) {
				stringBuilder.append("g^{a_" + i + "} =  " + shareholder.getFeldmanValues(i) + "<br/>\n");
			}
			stringBuilder.append("<p/>\n");

			// Print Share Information
			final String readLink = "https://" + ourIp + ":" + ourPort + "/read?secretName=" + secretName;
			final String enableLink = "https://" + ourIp + ":" + ourPort + "/enable?secretName=" + secretName;
			final String disableLink = "https://" + ourIp + ":" + ourPort + "/disable?secretName=" + secretName;
			final String deleteLink = "https://" + ourIp + ":" + ourPort + "/delete?secretName=" + secretName;
			final String recoverLink = "https://" + ourIp + ":" + ourPort + "/recover?secretName=" + secretName;
			stringBuilder.append("<b>Share Information:</b><br/>\n");
			stringBuilder.append(CommonConfiguration.HASH_ALGORITHM + "(s_" + serverIndex + ")        =  "
					+ shareholder.getShare1Hash() + " (<a href=\"" + readLink
					+ "\">View Share</a>) <br/>\n");
			if (shareholder.getShare1() != null) {
				stringBuilder.append("exists  =  TRUE (<a href=\"" + deleteLink + "\">Delete Share</a>) <br/>\n");
			} else {
				stringBuilder.append("exists  =  FALSE (<a href=\"" + recoverLink + "\">Recover Share</a>) <br/>\n");
			}
			if (shareholder.isEnabled()) {
				stringBuilder.append("status  =  ENABLED (<a href=\"" + disableLink + "\">Disable Share</a>) <br/>\n");
			} else {
				stringBuilder.append("status  =  DISABLED (<a href=\"" + enableLink + "\">Enable Share</a>) <br/>\n");
			}
			stringBuilder.append("<p/>\n");
			
			stringBuilder.append("<b>Use Share:</b><br/>\n");
			stringBuilder.append("<form action=\"/exponentiate\" method=\"get\">");
			stringBuilder.append("<input type=\"hidden\" id=\"secretName\" name=\"secretName\" value=\"" + secretName + "\">");
			stringBuilder.append("x: <input type=\"text\" name=\"x\"> y: <input type=\"text\" name=\"y\"> <input type=\"submit\" value=\"Exponentiate\"> <br/>\n");
			stringBuilder.append("<p/>\n");
		}

		// Peers
		stringBuilder.append("<p/>\n");
		stringBuilder.append("<b>Peers:</b><br/>\n");

		int serverId = 0;
		for (final InetSocketAddress serverAddress : serverConfig.getServerAddresses()) {
			serverId++;
			final String serverIp = serverAddress.getHostString();
			final int serverPort = HttpRequestProcessor.BASE_HTTP_PORT + serverId;
			final String linkUrl = "https://" + serverIp + ":" + serverPort + "/info?secretName=" + secretName;
			stringBuilder.append(
					"server." + serverId + " = " + "<a href=\"" + linkUrl + "\">" + serverAddress + "</a><br/>\n");
		}
		stringBuilder.append("<p/>\n");

		stringBuilder.append("</tt>\n");
		stringBuilder.append("</body>\n");
		stringBuilder.append("</html>\n");

		return stringBuilder.toString();
	}

}