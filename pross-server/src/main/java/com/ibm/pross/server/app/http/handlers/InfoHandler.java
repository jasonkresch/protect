package com.ibm.pross.server.app.http.handlers;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentMap;

import org.json.simple.JSONArray;
import org.json.simple.JSONObject;

import com.ibm.pross.common.CommonConfiguration;
import com.ibm.pross.server.app.avpss.ApvssShareholder;
import com.ibm.pross.server.app.avpss.SharingState;
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
	public static final String EPOCH_NUMBER_FIELD = "epochNumber";
	public static final String OUTPUT_FORMAT_FIELD = "json";

	// Fields
	private final AccessEnforcement accessEnforcement;
	private final ServerConfiguration serverConfig;
	private final ConcurrentMap<String, ApvssShareholder> shareholders;

	public InfoHandler(final KeyLoader clientKeys, final AccessEnforcement accessEnforcement,
			final ServerConfiguration serverConfig, final ConcurrentMap<String, ApvssShareholder> shareholders) {
		super(clientKeys);
		this.shareholders = shareholders;
		this.serverConfig = serverConfig;
		this.accessEnforcement = accessEnforcement;
	}

	@Override
	public void authenticatedClientHandle(final HttpExchange exchange, final String username)
			throws IOException, UnauthorizedException, NotFoundException, BadRequestException {

		// Extract secret name from request
		final String queryString = exchange.getRequestURI().getQuery();
		final Map<String, List<String>> params = HttpRequestProcessor.parseQueryString(queryString);

		final String secretName = HttpRequestProcessor.getParameterValue(params, SECRET_NAME_FIELD);
		if (secretName == null) {
			throw new BadRequestException();
		}
		final Boolean outputJson = Boolean
				.parseBoolean(HttpRequestProcessor.getParameterValue(params, OUTPUT_FORMAT_FIELD));

		// Perform authentication
		accessEnforcement.enforceAccess(username, secretName, REQUEST_PERMISSION);

		// Do processing
		final ApvssShareholder shareholder = this.shareholders.get(secretName);
		if (shareholder == null) {
			throw new NotFoundException();
		}

		// Get epoch number from request
		final Long epochNumber;
		final List<String> epochNumbers = params.get(EPOCH_NUMBER_FIELD);
		if ((epochNumbers != null) && (epochNumbers.size() == 1)) {
			epochNumber = Long.parseLong(epochNumbers.get(0));
		} else {
			epochNumber = shareholder.getEpoch();
		}

		// Create response
		final String response = getSecretInfo(shareholder, secretName, epochNumber, serverConfig, outputJson);
		final byte[] binaryResponse = response.getBytes(StandardCharsets.UTF_8);

		// Write headers
		// exchange.getResponseHeaders().add("Strict-Transport-Security", "max-age=300;
		// includeSubdomains");
		exchange.sendResponseHeaders(HttpStatusCode.SUCCESS, binaryResponse.length);

		// Write response
		try (final OutputStream os = exchange.getResponseBody();) {
			os.write(binaryResponse);
		}
	}

	@SuppressWarnings("unchecked")
	private static String getSecretInfo(final ApvssShareholder shareholder, final String secretName,
			final Long epochNumber, final ServerConfiguration serverConfig, final boolean outputJson) throws BadRequestException {

		// Prevent invalid epochs from being accessed
		if ((epochNumber < 0) || (epochNumber > shareholder.getEpoch())) {
			throw new BadRequestException();
		}
		
		final int serverIndex = shareholder.getIndex();
		
		if (outputJson) {
			// Just return the epoch, and public key
			
			// Return the result in json
			final JSONObject obj = new JSONObject();
			obj.put("responder", new Integer(serverIndex));
			obj.put("epoch", new Long(shareholder.getEpoch()));

			JSONArray inputPoint = new JSONArray();
			inputPoint.add(shareholder.getSecretPublicKey().getX().toString());
			inputPoint.add(shareholder.getSecretPublicKey().getY().toString());
			obj.put("public_key", inputPoint);

			return obj.toJSONString() + "\n";
		}

		// This server
		final InetSocketAddress thisServerAddress = serverConfig.getServerAddresses().get(serverIndex - 1);
		final String ourIp = thisServerAddress.getAddress().getHostAddress();
		final int ourPort = HttpRequestProcessor.BASE_HTTP_PORT + serverIndex;

		// Create response
		final StringBuilder stringBuilder = new StringBuilder();
		stringBuilder.append("<html>\n");
		stringBuilder.append("<head>\n");
		if (epochNumber == shareholder.getEpoch()) {
			// Refresh only if looking at the latest
			final String linkUrl = "https://" + ourIp + ":" + ourPort + "/info?secretName=" + secretName;
			stringBuilder.append("<meta http-equiv=\"refresh\" content=\"10;URL='" + linkUrl + "'\">\n");
		}
		stringBuilder.append("</head>\n");
		stringBuilder.append("<body>\n");
		stringBuilder.append("<pre>\n");

		// Shareholder information
		stringBuilder.append("This is <a href=\"/\">shareholder #" + serverIndex + "</a>"
				+ " running <a href=\"https://github.com/jasonkresch/protect\">PROTECT</a>,"
				+ " a <b>P</b>latform for <b>Ro</b>bust <b>T</b>hr<b>e</b>shold <b>C</b>ryp<b>t</b>ography.\n");
		stringBuilder.append("<p/>");

		// Secret Info
		stringBuilder.append("<b>Information for \"" + secretName + "\":</b>\n");
		final int n = shareholder.getN();
		final int k = shareholder.getK();
		if (shareholder.getSecretPublicKey() == null) {
			// final String linkUrl = "https://" + ourIp + ":" + ourPort +
			// "/generate?secretName=" + secretName;
			stringBuilder.append("<p>Secret not yet established.\n\n");

			/// "(<a href=\"" + linkUrl + "\">Perform DKG</a>)\n");

			stringBuilder.append("<form action=\"/store\" method=\"get\">");
			stringBuilder.append("<b>Prepare Share for DKG (optional):</b> ");
			stringBuilder.append(
					"<input type=\"hidden\" id=\"secretName\" name=\"secretName\" value=\"" + secretName + "\">");
			stringBuilder.append("s_" + serverIndex
					+ ": <input type=\"text\" name=\"share\"> <input type=\"submit\" value=\"Store Share\"> </form>\n");

			stringBuilder.append("<form action=\"/generate\" method=\"get\">");
			stringBuilder.append("<b>Create Shared Secret:</b> ");
			stringBuilder.append(
					"<input type=\"hidden\" id=\"secretName\" name=\"secretName\" value=\"" + secretName + "\">");
			stringBuilder.append("<input type=\"submit\" value=\"Initiate DKG\"></form>\n");
			stringBuilder.append("<p/>");

			// stringBuilder.append("<b>Set RSA Share and Modulus:</b>\n");
			// stringBuilder.append("<form action=\"/store\" method=\"get\">");
			// stringBuilder.append(
			// "<input type=\"hidden\" id=\"secretName\" name=\"secretName\" value=\"" +
			// secretName + "\">");
			// stringBuilder.append("s_" + serverIndex
			// + ": <input type=\"text\" name=\"share\"> modulus: <input type=\"text\"
			// name=\"modulus\"> <input type=\"submit\" value=\"Store RSA Share\">
			// </form>\n");
			// stringBuilder.append("<p/>");

			stringBuilder.append("<p/>");
		} else {
			stringBuilder.append("sharing_type      =  " + shareholder.getSharingType() + "\n");
			stringBuilder.append("g^{s}             =  " + shareholder.getSecretPublicKey() + "\n");
			stringBuilder.append("number_of_shares  =  " + shareholder.getN() + "\n");
			stringBuilder.append("threshold         =  " + shareholder.getK() + "\n");
			stringBuilder.append("creation_time     =  " + shareholder.getCreationTime() + "\n");
			stringBuilder.append("last_refresh      =  " + shareholder.getLastRefreshTime() + "\n");
			stringBuilder.append("refresh_frequency =  " + shareholder.getRefreshFrequency() + " seconds\n");
			stringBuilder.append("<p/>");

			// Print Field Information
			stringBuilder.append("<b>Field Information:</b>\n");
			stringBuilder.append("prime_modulus     =  " + CommonConfiguration.CURVE.getR() + "\n");
			stringBuilder.append("curve_oid         =  " + CommonConfiguration.CURVE.getOid() + " ("
					+ CommonConfiguration.CURVE.getName() + ")\n");
			stringBuilder.append("generator         =  " + CommonConfiguration.g + "\n");
			stringBuilder.append("<p/>");

			// Print Epoch information
			final SharingState sharingState = shareholder.getSharing(epochNumber);
			stringBuilder.append("<b>Epoch:</b>\n");
			final long firstEpoch = 0;
			final long previousEpoch = epochNumber - 1;
			final long nextEpoch = epochNumber + 1;
			final long latestEpoch = shareholder.getEpoch();
			final String infoFirstEpoch = "https://" + ourIp + ":" + ourPort + "/info?secretName=" + secretName
					+ "&epochNumber=" + firstEpoch;
			final String infoPreviousEpoch = "https://" + ourIp + ":" + ourPort + "/info?secretName=" + secretName
					+ "&epochNumber=" + previousEpoch;
			final String infoNextEpoch = "https://" + ourIp + ":" + ourPort + "/info?secretName=" + secretName
					+ "&epochNumber=" + nextEpoch;
			final String infoLastEpoch = "https://" + ourIp + ":" + ourPort + "/info?secretName=" + secretName
					+ "&epochNumber=" + latestEpoch;
			stringBuilder.append("epoch_number      =  ");
			stringBuilder.append("<a href=\"" + infoFirstEpoch + "\"><<</a> ");
			stringBuilder.append("<a href=\"" + infoPreviousEpoch + "\"><</a> ");
			stringBuilder.append(epochNumber);
			stringBuilder.append(" <a href=\"" + infoNextEpoch + "\">></a> ");
			stringBuilder.append("<a href=\"" + infoLastEpoch + "\">>></a>\n");
			stringBuilder.append("completion_time   =  " + sharingState.getCreationTime() + "\n");

			stringBuilder.append("<p/>");

			// Print share verification keys
			stringBuilder.append("<b>Share Verification Keys:</b>\n");
			for (int i = 1; i <= n; i++) {
				stringBuilder.append("g^{s_" + i + "} =  " + sharingState.getSharePublicKeys()[i] + "\n");
			}
			stringBuilder.append("<p/>");

			// Print Feldman Coefficients
			stringBuilder.append("<b>Feldman Coefficients:</b>\n");
			for (int i = 0; i < k; i++) {
				stringBuilder.append("g^{a_" + i + "} =  " + sharingState.getFeldmanValues()[i] + "\n");
			}
			stringBuilder.append("<p/>");

			// Print Share Information
			final String readLink = "https://" + ourIp + ":" + ourPort + "/read?secretName=" + secretName;
			final String enableLink = "https://" + ourIp + ":" + ourPort + "/enable?secretName=" + secretName;
			final String disableLink = "https://" + ourIp + ":" + ourPort + "/disable?secretName=" + secretName;
			final String deleteLink = "https://" + ourIp + ":" + ourPort + "/delete?secretName=" + secretName;
			final String recoverLink = "https://" + ourIp + ":" + ourPort + "/recover?secretName=" + secretName;
			stringBuilder.append("<b>Share Information:</b>\n");
			stringBuilder.append(CommonConfiguration.HASH_ALGORITHM + "(s_" + serverIndex + ")  =  "
					+ sharingState.getShare1Hash() + "\n");
			if (sharingState.getShare1() != null) {
				stringBuilder.append("exists        =  TRUE     (<a href=\"" + readLink + "\">Read Share</a>)  (<a href=\"" + deleteLink + "\">Delete Share</a>) \n");
			} else {
				stringBuilder.append("exists        =  FALSE    (<a href=\"" + readLink + "\">Read Share</a>)  (<a href=\"" + recoverLink + "\">Recover Share</a>) \n");
			}
			if (shareholder.isEnabled()) {
				stringBuilder.append("status        =  ENABLED  (<a href=\"" + disableLink + "\">Disable Share</a>) \n");
			} else {
				stringBuilder.append("status        =  DISABLED (<a href=\"" + enableLink + "\">Enable Share</a>) \n");
			}
			stringBuilder.append("<p/>");

			// TODO: Consider: only showing this if the share exists?
			stringBuilder.append("<b>Use Share:</b>\n");
			stringBuilder.append("<form action=\"/exponentiate\" method=\"get\">");
			stringBuilder.append(
					"<input type=\"hidden\" id=\"secretName\" name=\"secretName\" value=\"" + secretName + "\">");
			stringBuilder.append(
					"x: <input type=\"text\" name=\"x\"> y: <input type=\"text\" name=\"y\"> <input type=\"submit\" value=\"Exponentiate\"> \n");
			stringBuilder.append("<p/>");

		}

		// Peers
		stringBuilder.append("<b>Peers:</b>\n");

		int serverId = 0;
		for (final InetSocketAddress serverAddress : serverConfig.getServerAddresses()) {
			serverId++;
			final String serverIp = serverAddress.getAddress().getHostAddress();
			final int serverPort = HttpRequestProcessor.BASE_HTTP_PORT + serverId;
			final String linkUrl = "https://" + serverIp + ":" + serverPort + "/info?secretName=" + secretName;
			stringBuilder
					.append("server." + serverId + " = " + "<a href=\"" + linkUrl + "\">" + serverAddress + "</a>\n");
		}
		stringBuilder.append("<p/>\n");

		stringBuilder.append("</pre>\n");
		stringBuilder.append("</body>\n");
		stringBuilder.append("</html>\n");

		return stringBuilder.toString();
	}

}