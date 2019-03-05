package com.ibm.pross.server.app.http.handlers;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentMap;

import com.ibm.pross.server.app.avpss.ApvssShareholder;
import com.ibm.pross.server.app.http.HttpRequestProcessor;
import com.ibm.pross.server.app.http.HttpStatusCode;
import com.ibm.pross.server.configuration.permissions.AccessEnforcement;
import com.ibm.pross.server.configuration.permissions.ClientPermissions.Permissions;
import com.ibm.pross.server.configuration.permissions.exceptions.BadRequestException;
import com.ibm.pross.server.configuration.permissions.exceptions.NotFoundException;
import com.ibm.pross.server.configuration.permissions.exceptions.ResourceUnavailableException;
import com.ibm.pross.server.configuration.permissions.exceptions.UnauthorizedException;
import com.sun.net.httpserver.HttpExchange;

import bftsmart.reconfiguration.util.sharedconfig.KeyLoader;

/**
 * This handler deletes a share of a secret, preventing use in exponentiation,
 * reading, signing and other operations. Client's must have a specific
 * authorization to be able to invoke this method. If the secret is not found a
 * 404 is returned. If the client is not authorized a 403 is returned.
 * 
 * Note that the share may be restored automatically by the periodic refresh,
 * and also may be manually recovered via the recover operation. Permanent
 * deletion requires deleting a sufficient number of shares within the refresh
 * period to make recovery impossible.
 */
@SuppressWarnings("restriction")
public class DeleteHandler extends AuthenticatedRequestHandler {

	public static final Permissions REQUEST_PERMISSION = Permissions.DELETE;

	// Query name
	public static final String SECRET_NAME_FIELD = "secretName";

	// Fields
	private final AccessEnforcement accessEnforcement;
	private final ConcurrentMap<String, ApvssShareholder> shareholders;

	public DeleteHandler(final KeyLoader clientKeys, final AccessEnforcement accessEnforcement,
			final ConcurrentMap<String, ApvssShareholder> shareholders) {
		super(clientKeys);
		this.shareholders = shareholders;
		this.accessEnforcement = accessEnforcement;
	}

	@Override
	public void authenticatedClientHandle(final HttpExchange exchange, final Integer clientId) throws IOException,
			UnauthorizedException, NotFoundException, BadRequestException, ResourceUnavailableException {

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

		shareholder.deleteShare();

		// Create response
		final String response = secretName + " has been DELETED.\n";
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

}