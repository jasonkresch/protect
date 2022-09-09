package com.ibm.pross.server.app.http.handlers;

import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

import org.json.simple.JSONArray;
import org.json.simple.JSONObject;

import com.ibm.pross.common.config.KeyLoader;
import com.ibm.pross.common.exceptions.http.BadRequestException;
import com.ibm.pross.common.exceptions.http.HttpStatusCode;
import com.ibm.pross.common.exceptions.http.NotFoundException;
import com.ibm.pross.common.exceptions.http.ResourceUnavailableException;
import com.ibm.pross.common.exceptions.http.UnauthorizedException;
import com.ibm.pross.common.util.crypto.rsa.threshold.sign.client.RsaSharing;
import com.ibm.pross.common.util.crypto.rsa.threshold.sign.data.SignatureResponse;
import com.ibm.pross.common.util.crypto.rsa.threshold.sign.math.ThresholdSignatures;
import com.ibm.pross.common.util.crypto.rsa.threshold.sign.server.RsaShareConfiguration;
import com.ibm.pross.common.util.crypto.rsa.threshold.sign.server.ServerPublicConfiguration;
import com.ibm.pross.common.util.crypto.schnorr.NonceCommitment;
import com.ibm.pross.common.util.shamir.ShamirShare;
import com.ibm.pross.server.app.avpss.ApvssShareholder;
import com.ibm.pross.server.app.avpss.ApvssShareholder.SharingType;
import com.ibm.pross.server.app.http.HttpRequestProcessor;
import com.ibm.pross.server.configuration.permissions.AccessEnforcement;
import com.ibm.pross.server.configuration.permissions.ClientPermissions.Permissions;
import com.sun.net.httpserver.HttpExchange;

/**
 * This handler caches a nonce for use in FROST Schnorr Signature generation.
 * Client's must have a specific authorization to be able to invoke this method.
 * If the secret is not found a 404 is returned. If the client is not authorized
 * a 403 is returned.
 */
@SuppressWarnings("restriction")
public class SchnorrNonceHandler extends AuthenticatedClientRequestHandler {

	public static final Permissions REQUEST_PERMISSION = Permissions.SIGN;

	// Query names
	public static final String SECRET_NAME_FIELD = "secretName";
	public static final String NONCE_ID = "nonce-id";

	// Fields
	private final AccessEnforcement accessEnforcement;
	private final ConcurrentMap<String, ApvssShareholder> shareholders;
	private final ConcurrentMap<UUID, NonceCommitment> nonceCommitments;

	public SchnorrNonceHandler(final KeyLoader clientKeys, final AccessEnforcement accessEnforcement,
			final ConcurrentMap<String, ApvssShareholder> shareholders, ConcurrentHashMap<UUID, NonceCommitment> nonceCommitments) {
		super(clientKeys);
		this.shareholders = shareholders;
		this.accessEnforcement = accessEnforcement;
		this.nonceCommitments = nonceCommitments;
	}

	@SuppressWarnings("unchecked")
	@Override
	public void authenticatedClientHandle(final HttpExchange exchange, final String username) throws IOException,
			UnauthorizedException, NotFoundException, BadRequestException, ResourceUnavailableException {

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

		// Extract nonce ID from request
		final String nonceId = HttpRequestProcessor.getParameterValue(params, NONCE_ID);
		if (nonceId == null) {
			throw new BadRequestException();
		}
		final UUID nonceUUID;
		try {
			nonceUUID = UUID.fromString(nonceId);
		} catch (Throwable t) {
			throw new BadRequestException();
		}

		// Ensure the secret is of the supported type
		if (!(SharingType.PEDERSEN_DKG.equals(shareholder.getSharingType())
				|| SharingType.FELDMAN_DKG.equals(shareholder.getSharingType()))) {
			throw new BadRequestException();
		}

	
		// Do processing
		final long startTime = System.nanoTime();
		final NonceCommitment nonceCommitment = NonceCommitment.generateCommitment(ApvssShareholder.curve);
		this.nonceCommitments.putIfAbsent(nonceUUID, nonceCommitment);
		final NonceCommitment existingCommitment = this.nonceCommitments.get(nonceUUID);
		final long endTime = System.nanoTime();

		// Compute processing time
		final long processingTimeUs = (endTime - startTime) / 1_000;

		// Create response
		final int serverIndex = shareholder.getIndex();
		final long epoch = shareholder.getEpoch();
		
		// Return the result in json
		final JSONObject obj = new JSONObject();
		obj.put("responder", new Integer(serverIndex));
		obj.put("epoch", new Long(epoch));

		// gE
		JSONArray gE = new JSONArray();
		gE.add(existingCommitment.getgE().getX().toString());
		gE.add(existingCommitment.getgE().getY().toString());
		obj.put("ge", gE);
		
		// gD
		JSONArray gD = new JSONArray();
		gD.add(existingCommitment.getgD().getX().toString());
		gD.add(existingCommitment.getgD().getY().toString());
		obj.put("gd", gD);

		obj.put("compute_time_us", new Long(processingTimeUs));

		String response = obj.toJSONString() + "\n";

		final byte[] binaryResponse = response.getBytes(StandardCharsets.UTF_8);

		// Write headers
		exchange.sendResponseHeaders(HttpStatusCode.SUCCESS, binaryResponse.length);

		// Write response
		try (final OutputStream os = exchange.getResponseBody();) {
			os.write(binaryResponse);
		}
	}

}