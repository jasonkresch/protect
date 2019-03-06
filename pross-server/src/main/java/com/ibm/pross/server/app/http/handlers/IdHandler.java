package com.ibm.pross.server.app.http.handlers;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Set;
import java.util.concurrent.ConcurrentMap;

import com.ibm.pross.server.app.avpss.ApvssShareholder;
import com.ibm.pross.server.app.http.HttpStatusCode;
import com.ibm.pross.server.configuration.permissions.AccessEnforcement;
import com.ibm.pross.server.configuration.permissions.ClientPermissions;
import com.ibm.pross.server.configuration.permissions.ClientPermissions.Permissions;
import com.ibm.pross.server.configuration.permissions.exceptions.BadRequestException;
import com.ibm.pross.server.configuration.permissions.exceptions.NotFoundException;
import com.ibm.pross.server.configuration.permissions.exceptions.UnauthorizedException;
import com.sun.net.httpserver.HttpExchange;

import bftsmart.reconfiguration.util.sharedconfig.KeyLoader;

/**
 * This handler returns the id of the authenticated client
 */
@SuppressWarnings("restriction")
public class IdHandler extends AuthenticatedClientRequestHandler {

	private final AccessEnforcement accessEnforcement;
	private final ConcurrentMap<String, ApvssShareholder> shareholders;

	public IdHandler(final KeyLoader clientKeys, final AccessEnforcement accessEnforcement, final ConcurrentMap<String, ApvssShareholder> shareholders) {
		super(clientKeys);
		this.accessEnforcement = accessEnforcement;
		this.shareholders = shareholders;
	}

	@Override
	public void authenticatedClientHandle(final HttpExchange exchange, final String username)
			throws IOException, UnauthorizedException, NotFoundException, BadRequestException {

		// Create response
		final String authenticatedAs;
		if (username != null) {
			authenticatedAs = "You have authenticated as Client " + username + ".\n";
		} else {
			authenticatedAs = "You have failed to authenticate and are Anonymous.\n";
		}

		final String permissionList = getPermissions(username, shareholders.keySet());

		final String response = authenticatedAs + permissionList;
		final byte[] binaryResponse = response.getBytes(StandardCharsets.UTF_8);

		// Write headers
		exchange.sendResponseHeaders(HttpStatusCode.SUCCESS, binaryResponse.length);

		// Write response
		try (final OutputStream os = exchange.getResponseBody();) {
			os.write(binaryResponse);
		}
	}

	private String getPermissions(final String username, final Set<String> secretNames) throws NotFoundException {

		final StringBuilder stringBuilder = new StringBuilder();
		
		for (String secretName : secretNames) {
			
			stringBuilder.append("\n");
			stringBuilder.append("Permissions for '" + secretName + "':\n");
			
			for (Permissions permission : ClientPermissions.Permissions.values()) {
				try {
					accessEnforcement.enforceAccess(username, secretName, permission);
					stringBuilder.append("  " + permission + "\n");
				} catch (UnauthorizedException e) {
					// Ignore
				}
			}
		}
		
		return stringBuilder.toString();

	}

}