package com.ibm.pross.server.app.http.handlers;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.Map.Entry;
import java.util.concurrent.ConcurrentMap;

import com.ibm.pross.server.app.avpss.ApvssShareholder;
import com.ibm.pross.server.app.http.HttpRequestProcessor;
import com.ibm.pross.server.app.http.HttpStatusCode;
import com.sun.net.httpserver.HttpExchange;

import bftsmart.reconfiguration.util.sharedconfig.ServerConfiguration;

/**
 * This handler returns basic configuration information about the server,
 * including this server's id, the threshold parameters, identities of other
 * servers (as links), and benchmark results.
 */
@SuppressWarnings("restriction")
public class RootHandler extends BaseHttpHandler {

	private final int serverIndex;
	private final ServerConfiguration serverConfiguration;
	final ConcurrentMap<String, ApvssShareholder> shareholders;

	public RootHandler(final int serverIndex, final ServerConfiguration serverConfiguration,
			final ConcurrentMap<String, ApvssShareholder> shareholders) {
		this.serverIndex = serverIndex;
		this.serverConfiguration = serverConfiguration;
		this.shareholders = shareholders;
	}

	@Override
	public void handleWithExceptions(final HttpExchange exchange) throws IOException {

		// Create response
		final StringBuilder stringBuilder = new StringBuilder();
		stringBuilder.append("<html>\n");
		stringBuilder.append("<body>\n");
		stringBuilder.append("<pre>\n");
		stringBuilder.append("This is <a href=\"/\">shareholder #" + this.serverIndex + "</a>"
				+ " running <a href=\"https://github.com/jasonkresch/protect\">PROTECT</a>,"
				+ " a <b>P</b>latform for <b>Ro</b>bust <b>T</b>hr<b>e</b>shold <b>C</b>ryp<b>t</b>ography.\n");
		stringBuilder.append("<p/>");

		// Config
		stringBuilder.append("<b>System Configuration:</b>\n");
		stringBuilder.append("num_servers          = " + serverConfiguration.getNumServers() + "\n");
		stringBuilder.append("threshold            = " + serverConfiguration.getReconstructionThreshold() + "\n");
		stringBuilder.append("max_safety_faults    = " + serverConfiguration.getMaxSafetyFaults() + "\n");
		stringBuilder.append("max_liveness_faults  = " + serverConfiguration.getMaxLivenessFaults() + "\n");
		stringBuilder.append("max_bft_faults       = " + serverConfiguration.getMaxBftFaults() + "\n");
		stringBuilder.append("<p/>");

		// Peers
		stringBuilder.append("<b>Peers:</b>\n");
		int serverId = 0;
		for (final InetSocketAddress serverAddress : this.serverConfiguration.getServerAddresses()) {
			serverId++;
			final String serverIp = serverAddress.getAddress().getHostAddress();
			final int serverPort = HttpRequestProcessor.BASE_HTTP_PORT + serverId;
			final String linkUrl = "https://" + serverIp + ":" + serverPort + "/";
			stringBuilder.append(
					"server." + serverId + " = " + "<a href=\"" + linkUrl + "\">" + serverAddress + "</a>\n");
		}
		stringBuilder.append("<p/>");

		// Secrets
		stringBuilder.append("<b>Secrets:</b>\n");
		final String ourHost = this.serverConfiguration.getServerAddresses().get(this.serverIndex - 1).getAddress().getHostAddress();
		final int ourPort = HttpRequestProcessor.BASE_HTTP_PORT + this.serverIndex;
		int secretId = 0;
		for (final Entry<String, ApvssShareholder> entry : this.shareholders.entrySet()) {
			secretId++;
			final String secretName = entry.getKey();
			final String linkUrl = "https://" + ourHost + ":" + ourPort + "/info?secretName=" + secretName;
			stringBuilder.append(secretId + ". " + "<a href=\"" + linkUrl + "\">" + secretName + "</a>\n");
		}
		stringBuilder.append("<p/>");

		// User authentication
		stringBuilder.append("<b>You:</b>\n");
		final String linkUrl = "https://" + ourHost + ":" + ourPort + "/id";
		stringBuilder.append("(<a href=\"" + linkUrl + "\">" + "Who am I" + "</a>)\n");
		stringBuilder.append("<p/>\n");

		stringBuilder.append("</tt>\n");
		stringBuilder.append("</body>\n");
		stringBuilder.append("</html>\n");
		final String response = stringBuilder.toString();
		final byte[] binaryResponse = response.getBytes(StandardCharsets.UTF_8);

		// Write headers
		exchange.sendResponseHeaders(HttpStatusCode.SUCCESS, binaryResponse.length);

		// Write response
		try (final OutputStream os = exchange.getResponseBody();) {
			os.write(binaryResponse);
		}
	}

}