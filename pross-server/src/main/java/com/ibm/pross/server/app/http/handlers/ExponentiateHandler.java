package com.ibm.pross.server.app.http.handlers;

import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentMap;

import com.ibm.pross.common.CommonConfiguration;
import com.ibm.pross.common.util.crypto.ecc.EcPoint;
import com.ibm.pross.server.app.avpss.ApvssShareholder;
import com.ibm.pross.server.app.http.HttpRequestProcessor;
import com.ibm.pross.server.app.http.HttpStatusCode;
import com.ibm.pross.server.configuration.permissions.AccessEnforcement;
import com.ibm.pross.server.configuration.permissions.ClientPermissions.Permissions;
import com.ibm.pross.server.configuration.permissions.exceptions.BadRequestException;
import com.ibm.pross.server.configuration.permissions.exceptions.NotFoundException;
import com.ibm.pross.server.configuration.permissions.exceptions.UnauthorizedException;
import com.sun.net.httpserver.HttpExchange;

import bftsmart.reconfiguration.util.sharedconfig.ServerConfiguration;

/**
 * This handler returns information about a secret. Client's must have a
 * specific authorization to be able to invoke this method. If the secret is not
 * found a 404 is returned. If the client is not authorized a 401 is returned.
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
public class ExponentiateHandler extends AuthenticatedClientRequestHandler {

	public static final Permissions REQUEST_PERMISSION = Permissions.EXPONENTIATE;

	// Query names
	public static final String SECRET_NAME_FIELD = "secretName";
	public static final String BASE_X_COORD = "x";
	public static final String BASE_Y_COORD = "y";

	// Fields
	private final AccessEnforcement accessEnforcement;
	private final ConcurrentMap<String, ApvssShareholder> shareholders;

	public ExponentiateHandler(final AccessEnforcement accessEnforcement,
			final ConcurrentMap<String, ApvssShareholder> shareholders) {
		this.shareholders = shareholders;
		this.accessEnforcement = accessEnforcement;
	}

	@Override
	public void authenticatedClientHandle(final HttpExchange exchange, final Integer clientId)
			throws IOException, UnauthorizedException, NotFoundException, BadRequestException {

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

		// Extract X-Coordinate from request
		final List<String> xCoords = params.get(BASE_X_COORD);
		if (xCoords == null || xCoords.size() != 1) {
			throw new BadRequestException();
		}
		final BigInteger xCoord = new BigInteger(xCoords.get(0));

		// Extract Y-Coordinate from request or compute it.
		final BigInteger yCoord;
		final List<String> yCoords = params.get(BASE_Y_COORD);
		if (yCoords != null && yCoords.size() == 1) {
			yCoord = new BigInteger(yCoords.get(0));
		} else {
			// Compute yCoordinate from xCoordinate
			final BigInteger ySquared = CommonConfiguration.CURVE.computeYSquared(xCoord);
			yCoord = CommonConfiguration.CURVE.getPointHasher().squareRoot(ySquared);
		}

		// Form an elliptic curve point
		final EcPoint basePoint = new EcPoint(xCoord, yCoord);

		// Ensure the resulting point exists on the curve
		if (!CommonConfiguration.CURVE.isPointOnCurve(basePoint)) {
			throw new BadRequestException();
		}

		// Do processing
		final ApvssShareholder shareholder = this.shareholders.get(secretName);
		if (shareholder == null) {
			throw new NotFoundException();
		}

		final int serverIndex = shareholder.getIndex();

		final long startTime = System.nanoTime();
		final EcPoint result = doExponentiation(shareholder, basePoint);
		final long endTime = System.nanoTime();

		// Compute processing time
		final long processingTimeUs = (endTime - startTime) / 1_000;

		// Create response
		final String response = basePoint + "^{s_" + serverIndex + "} = \n" +
				result + "\n\n"
				+ "Result computed in " + processingTimeUs + " microseconds using share #" + serverIndex + " of secret '" + secretName + "\n";
		final byte[] binaryResponse = response.getBytes(StandardCharsets.UTF_8);

		// Write headers
		exchange.sendResponseHeaders(HttpStatusCode.SUCCESS, binaryResponse.length);

		// Write response
		try (final OutputStream os = exchange.getResponseBody();) {
			os.write(binaryResponse);
		}
	}

	private EcPoint doExponentiation(final ApvssShareholder shareholder, EcPoint basePoint) throws NotFoundException {
		if (shareholder.getSecretPublicKey() == null) {
			throw new NotFoundException();
		} else {
			// Compute exponentiation using share
			return CommonConfiguration.CURVE.multiply(basePoint, shareholder.getShare1().getY());
		}

	}

}