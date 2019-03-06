package com.ibm.pross.server.app.http.handlers;

import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.AbstractMap.SimpleEntry;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentMap;

import org.json.simple.JSONObject;

import com.ibm.pross.server.app.avpss.ApvssShareholder;
import com.ibm.pross.server.app.http.HttpRequestProcessor;
import com.ibm.pross.server.app.http.HttpStatusCode;
import com.ibm.pross.server.configuration.permissions.exceptions.BadRequestException;
import com.ibm.pross.server.configuration.permissions.exceptions.NotFoundException;
import com.ibm.pross.server.configuration.permissions.exceptions.ResourceUnavailableException;
import com.ibm.pross.server.configuration.permissions.exceptions.UnauthorizedException;
import com.sun.net.httpserver.HttpExchange;

import bftsmart.reconfiguration.util.sharedconfig.KeyLoader;

/**
 * This handler is used by servers in share recovery operations. Servers are
 * only allowed to access their own share and the result is also encrypted with
 * the requester's Pallier public key.
 * 
 * If this the share is not found a 404 is returned. If the server is not
 * authorized a 403 is returned.
 */
@SuppressWarnings("restriction")
public class PartialHandler extends AuthenticatedServerRequestHandler {

	// Query name
	public static final String SECRET_NAME_FIELD = "secretName";

	// Fields
	private final ConcurrentMap<String, ApvssShareholder> shareholders;

	public PartialHandler(final KeyLoader serverKeys, final ConcurrentMap<String, ApvssShareholder> shareholders) {
		super(serverKeys);
		this.shareholders = shareholders;
	}

	@Override
	public void authenticatedServerHandle(final HttpExchange exchange, final Integer requesterId) throws IOException,
			UnauthorizedException, NotFoundException, BadRequestException, ResourceUnavailableException {

		// Extract secret name from request
		final String queryString = exchange.getRequestURI().getQuery();
		final Map<String, List<String>> params = HttpRequestProcessor.parseQueryString(queryString);
		final List<String> secretNames = params.get(SECRET_NAME_FIELD);
		if (secretNames == null || secretNames.size() != 1) {
			throw new BadRequestException();
		}
		final String secretName = secretNames.get(0);

		// Ensure shareholder exists
		final ApvssShareholder shareholder = this.shareholders.get(secretName);
		if (shareholder == null) {
			throw new NotFoundException();
		}
		// We lost our share too, we can't help in the rebuild
		if (shareholder.getShare1() == null) {
			throw new ResourceUnavailableException();
		}
		// TODO: Check if we also have recovered info regarding the last DKG or not,
		// otherwise we can't help

		// Perform authentication
		// Check that the server id is valid, and not equal to zero (in range 1 to n)
		if ((requesterId == null) || (requesterId < 1) || (requesterId > shareholder.getN())) {
			throw new UnauthorizedException();
		}

		// Create response
		final String response = computeEncryptedPartials(shareholder, secretName, requesterId);
		final byte[] binaryResponse = response.getBytes(StandardCharsets.UTF_8);

		// Write headers
		exchange.sendResponseHeaders(HttpStatusCode.SUCCESS, binaryResponse.length);

		// Write response
		try (final OutputStream os = exchange.getResponseBody();) {
			os.write(binaryResponse);
		}
	}

	@SuppressWarnings("unchecked")
	private static String computeEncryptedPartials(final ApvssShareholder shareholder, final String secretName,
			final Integer requesterId) throws NotFoundException {

		// This server
		final int serverIndex = shareholder.getIndex();

		// Epoch information
		final long epoch = shareholder.getEpoch();

		// Return encrypted partials
		final SimpleEntry<BigInteger, BigInteger> encryptedPartials = shareholder.computeEncryptedPartial(requesterId);
		final BigInteger encryptedShare1Part = encryptedPartials.getKey();
		final BigInteger encryptedShare2Part = encryptedPartials.getValue();

		// Return the result in json
		final JSONObject obj = new JSONObject();
		obj.put("responder", new Integer(serverIndex));
		obj.put("requester", new Integer(requesterId));
		obj.put("epoch", new Long(epoch));
		obj.put("share1_part", encryptedShare1Part.toString());
		obj.put("share2_part", encryptedShare2Part.toString());
		return obj.toJSONString() + "\n";

	}

}