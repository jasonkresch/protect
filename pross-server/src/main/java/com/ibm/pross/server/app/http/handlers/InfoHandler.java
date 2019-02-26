package com.ibm.pross.server.app.http.handlers;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;

import com.ibm.pross.server.app.http.HttpStatusCode;
import com.ibm.pross.server.configuration.permissions.AccessEnforcement;
import com.ibm.pross.server.configuration.permissions.ClientPermissions.Permissions;
import com.ibm.pross.server.configuration.permissions.UnauthorizedException;
import com.sun.net.httpserver.HttpExchange;

/**
 * This handler returns information about a secret. Client's must have a
 * specific authorization to be able to invoke this method. If the secret is not
 * found a 404 is returned. If the client is not authorized a 401 is returned.
 * 
 * <pre>
 * Information about the secret includes:
 * - The name of the secret
 * - The current epoch id of the secret (first is zero)
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
	
	// Field names
	public static final String SECRET_NAME_FIELD = "X-Secret-Name";

	@Override
	public void authenticatedClientHandle(final HttpExchange exchange, final Integer clientId)
			throws IOException, UnauthorizedException {

		// Extract secret name from request
		// TODO: Support get fields too!
		final String secretName = exchange.getRequestHeaders().getFirst(SECRET_NAME_FIELD);
		//final String secretName = (String) exchange.getAttribute(SECRET_NAME_FIELD);

		// Perform authentication
		final AccessEnforcement accessEnforcement = AccessEnforcement.INSECURE_DUMMY_ENFORCEMENT;
		accessEnforcement.enforceAccess(clientId, secretName, REQUEST_PERMISSION);

		// Do processing
		
		// Create response
		final String response = "Hi there! You asked for: " + secretName;
		final byte[] binaryResponse = response.getBytes(StandardCharsets.UTF_8);

		// Write headers
		exchange.sendResponseHeaders(HttpStatusCode.SUCCESS, binaryResponse.length);

		// Write response
		try (final OutputStream os = exchange.getResponseBody();) {
			os.write(binaryResponse);
		}
	}

}