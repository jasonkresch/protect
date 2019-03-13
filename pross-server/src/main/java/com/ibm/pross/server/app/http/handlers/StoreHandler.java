package com.ibm.pross.server.app.http.handlers;

import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentMap;

import com.ibm.pross.common.config.KeyLoader;
import com.ibm.pross.common.exceptions.http.BadRequestException;
import com.ibm.pross.common.exceptions.http.ConflictException;
import com.ibm.pross.common.exceptions.http.HttpStatusCode;
import com.ibm.pross.common.exceptions.http.InternalServerException;
import com.ibm.pross.common.exceptions.http.NotFoundException;
import com.ibm.pross.common.exceptions.http.ResourceUnavailableException;
import com.ibm.pross.common.exceptions.http.UnauthorizedException;
import com.ibm.pross.common.util.crypto.rsa.threshold.sign.client.RsaSharing;
import com.ibm.pross.server.app.avpss.ApvssShareholder;
import com.ibm.pross.server.app.http.HttpRequestProcessor;
import com.ibm.pross.server.configuration.permissions.AccessEnforcement;
import com.ibm.pross.server.configuration.permissions.ClientPermissions.Permissions;
import com.sun.net.httpserver.HttpExchange;

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

	// Required parameters
	public static final String SECRET_NAME_FIELD = "secretName";
	public static final String SHARE_VALUE = "share";

	// RSA query parameters
	public static final String MODULUS_VALUE = "n";
	public static final String PUBLIC_EXPONENT_VALUE = "e";
	public static final String VERIFICATION_BASE = "v";
	public static final String VERIFICATION_KEYS = "v_";

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
	public void authenticatedClientHandle(final HttpExchange exchange, final String username)
			throws IOException, UnauthorizedException, NotFoundException, BadRequestException,
			ResourceUnavailableException, ConflictException, InternalServerException {

		// Extract secret name from request
		final String queryString = exchange.getRequestURI().getQuery();
		final Map<String, List<String>> params = HttpRequestProcessor.parseQueryString(queryString);

		final String secretName = HttpRequestProcessor.getParameterValue(params, SECRET_NAME_FIELD);
		if (secretName == null) {
			throw new BadRequestException();
		}

		// Perform authentication
		accessEnforcement.enforceAccess(username, secretName, REQUEST_PERMISSION);

		// Ensure shareholder exists
		final ApvssShareholder shareholder = this.shareholders.get(secretName);
		if (shareholder == null) {
			throw new NotFoundException();
		}
		// Make sure secret is not disabled
		if (!shareholder.isEnabled()) {
			throw new ResourceUnavailableException();
		}
		// If DKG already started, it is too late, but we allow RSA keys to be updated
		if ((shareholder.getSharingType() != null)) {
			throw new ConflictException();
		}

		// Parse values from RSA storage operation
		final String nStr = HttpRequestProcessor.getParameterValue(params, MODULUS_VALUE);
		final BigInteger n = (nStr == null) ? null : new BigInteger(nStr);

		final String eStr = HttpRequestProcessor.getParameterValue(params, PUBLIC_EXPONENT_VALUE);
		final BigInteger e = (eStr == null) ? null : new BigInteger(eStr);

		final String vStr = HttpRequestProcessor.getParameterValue(params, VERIFICATION_BASE);
		final BigInteger v = (vStr == null) ? null : new BigInteger(vStr);

		final BigInteger[] verificationKeys = new BigInteger[shareholder.getN()];
		for (int i = 1; i <= shareholder.getN(); i++) {
			final String vStrI = HttpRequestProcessor.getParameterValue(params, VERIFICATION_KEYS + i);
			verificationKeys[i - 1] = (vStrI == null) ? null : new BigInteger(vStrI);
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
			if ((e != null) && (n != null) && (v != null)) {
				// Store RSA share, e and exponent n
				RSAPublicKeySpec spec = new RSAPublicKeySpec(n, e);
				KeyFactory keyFactory;
				try {
					keyFactory = KeyFactory.getInstance("RSA");

					final RsaSharing rsaSharing = new RsaSharing(shareholder.getN(), shareholder.getK(), (RSAPublicKey) keyFactory.generatePublic(spec), null, null, v, verificationKeys);
					shareholder.setRsaSecret(shareValue, rsaSharing);
					response = "RSA share have been stored.";
				}
				 catch ( NoSuchAlgorithmException | InvalidKeySpecException e1) {
					 throw new InternalServerException();
				 }
			} else {
				shareholder.setStoredShareOfSecret(shareValue);
				response = "s_" + serverIndex + " has been stored, DKG will use it for representing '" + secretName
						+ "' in the DKG.";
			}
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