package com.ibm.pross.server.app.http.handlers;

import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
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
import com.ibm.pross.server.configuration.permissions.exceptions.ConflictException;
import com.ibm.pross.server.configuration.permissions.exceptions.NotFoundException;
import com.ibm.pross.server.configuration.permissions.exceptions.ResourceUnavailableException;
import com.ibm.pross.server.configuration.permissions.exceptions.UnauthorizedException;
import com.sun.net.httpserver.HttpExchange;

import bftsmart.reconfiguration.util.sharedconfig.KeyLoader;

/**
 * This handler pre-stores a share of the secret Client's must have a specific
 * authorization to be able to invoke this method. The client must invoke this
 * method on each of the shareholders providing each with a unique share of the
 * secret before performing a generate in order to guarantee correct storage of
 * the secret.
 * 
 * If the secret is not found a 404 is returned. If the client is not authorized
 * a 403 is returned.
 */
@SuppressWarnings("restriction")
public class StoreHandler extends AuthenticatedClientRequestHandler {

	public static final Permissions REQUEST_PERMISSION = Permissions.STORE;

	// Query names
	public static final String SECRET_NAME_FIELD = "secretName";
	public static final String SHARE_VALUE = "share";

	// Fields
	private final AccessEnforcement accessEnforcement;
	private final ConcurrentMap<String, ApvssShareholder> shareholders;

	public StoreHandler(final KeyLoader clientKeys, final AccessEnforcement accessEnforcement,
			final ConcurrentMap<String, ApvssShareholder> shareholders) {
		super(clientKeys);
		this.shareholders = shareholders;
		this.accessEnforcement = accessEnforcement;
	}

	@Override
	public void authenticatedClientHandle(final HttpExchange exchange, final Integer clientId) throws IOException,
			UnauthorizedException, NotFoundException, BadRequestException, ResourceUnavailableException, ConflictException {

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

		// Ensure shareholder exists
		final ApvssShareholder shareholder = this.shareholders.get(secretName);
		if (shareholder == null) {
			throw new NotFoundException();
		}
		// Make sure secret is not disabled
		if (!shareholder.isEnabled()) {
			throw new ResourceUnavailableException();
		}
		// If DKG already started, it is too late
		if (shareholder.getSharingType() != null) {
			throw new ConflictException();
		}

		// Prepare to formulate response
		final int serverIndex = shareholder.getIndex();
		final String response;
		
		// Extract share from the request
		final List<String> shareValues = params.get(SHARE_VALUE);
		if ((shareValues == null) || (shareValues.size() != 1) || (shareValues.get(0) == null)) {
			// Unset the stored value
			shareholder.setStoredShareOfSecret(null);
			response = "s_" + serverIndex + " has been unset, DKG will use a random value for '" + secretName + "'.";
		} else {
			final BigInteger shareValue = new BigInteger(shareValues.get(0));
			shareholder.setStoredShareOfSecret(shareValue);
			response = "s_" + serverIndex + " has been stored, DKG will use it for representing '" + secretName + "' in the DKG.";
		}

		// Create response
		final byte[] binaryResponse = response.getBytes(StandardCharsets.UTF_8);

		// Write headers
		exchange.sendResponseHeaders(HttpStatusCode.SUCCESS, binaryResponse.length);

		// Write response
		try (final OutputStream os = exchange.getResponseBody();) {
			os.write(binaryResponse);
		}
	}

}