package com.ibm.pross.server.app.http.handlers;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.ConcurrentMap;

import com.ibm.pross.common.config.KeyLoader;
import com.ibm.pross.common.exceptions.http.BadRequestException;
import com.ibm.pross.common.exceptions.http.HttpStatusCode;
import com.ibm.pross.common.exceptions.http.NotFoundException;
import com.ibm.pross.common.exceptions.http.UnauthorizedException;
import com.ibm.pross.server.app.avpss.ApvssShareholder;
import com.ibm.pross.server.configuration.permissions.AccessEnforcement;
import com.ibm.pross.server.configuration.permissions.ClientPermissions;
import com.ibm.pross.server.configuration.permissions.ClientPermissions.Permissions;
import com.sun.net.httpserver.HttpExchange;

/**
 * This handler returns the id of the authenticated client
 */
@SuppressWarnings("restriction")
public class IdHandler extends AuthenticatedClientRequestHandler {

	private final AccessEnforcement accessEnforcement;
	private final ConcurrentMap<String, ApvssShareholder> shareholders;

	public IdHandler(final KeyLoader clientKeys, final AccessEnforcement accessEnforcement,
			final ConcurrentMap<String, ApvssShareholder> shareholders) {
		super(clientKeys);
		this.accessEnforcement = accessEnforcement;
		this.shareholders = shareholders;
	}

	@Override
	public void authenticatedClientHandle(final HttpExchange exchange, final String username)
			throws IOException, UnauthorizedException, NotFoundException, BadRequestException {

		final StringBuilder stringBuilder = new StringBuilder();

		stringBuilder.append("<html>\n");
		stringBuilder.append("<body>\n");
		stringBuilder.append("<pre>\n");

		// Create response
		if (username != null) {
			stringBuilder.append("You have authenticated as '<b>" + username + "</b>'.\n");
		} else {
			stringBuilder.append("You have failed to authenticate and are Anonymous.\n");
		}

		stringBuilder.append("\n");
		stringBuilder.append("You have the following permissions:\n");

		for (String secretName : shareholders.keySet()) {

			stringBuilder.append("\n");
			stringBuilder.append("<b>" + secretName + "</b>\n");
			stringBuilder.append("<ul>");

			for (Permissions permission : ClientPermissions.Permissions.values()) {
				try {
					accessEnforcement.enforceAccess(username, secretName, permission);
					stringBuilder.append("<li>" + permission + "</li>");
				} catch (UnauthorizedException e) {
					// Ignore
				}
			}
			stringBuilder.append("</ul>");
		}

		stringBuilder.append("</pre>\n");
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