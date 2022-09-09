package com.ibm.pross.server.app.http.handlers;

import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.List;
import java.util.Map;
import java.util.SortedMap;
import java.util.TreeMap;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

import org.apache.commons.codec.DecoderException;
import org.json.simple.JSONObject;

import com.ibm.pross.common.config.CommonConfiguration;
import com.ibm.pross.common.config.KeyLoader;
import com.ibm.pross.common.exceptions.http.BadRequestException;
import com.ibm.pross.common.exceptions.http.HttpStatusCode;
import com.ibm.pross.common.exceptions.http.NotFoundException;
import com.ibm.pross.common.exceptions.http.ResourceUnavailableException;
import com.ibm.pross.common.exceptions.http.UnauthorizedException;
import com.ibm.pross.common.util.crypto.ecc.EcPoint;
import com.ibm.pross.common.util.crypto.schnorr.NonceCommitment;
import com.ibm.pross.common.util.serialization.HexUtil;
import com.ibm.pross.common.util.serialization.Parse;
import com.ibm.pross.common.util.shamir.Polynomials;
import com.ibm.pross.common.util.shamir.ShamirShare;
import com.ibm.pross.server.app.avpss.ApvssShareholder;
import com.ibm.pross.server.app.avpss.ApvssShareholder.SharingType;
import com.ibm.pross.server.app.http.HttpRequestProcessor;
import com.ibm.pross.server.configuration.permissions.AccessEnforcement;
import com.ibm.pross.server.configuration.permissions.ClientPermissions.Permissions;
import com.sun.net.httpserver.HttpExchange;

/**
 * This handler performs an exponentiation using a share of a secret. Client's
 * must have a specific authorization to be able to invoke this method. If the
 * secret is not found a 404 is returned. If the client is not authorized a 403
 * is returned.
 */
@SuppressWarnings("restriction")
public class SchnorrSignHandler extends AuthenticatedClientRequestHandler {

	public static final Permissions REQUEST_PERMISSION = Permissions.SIGN;

	// Query names
	public static final String SECRET_NAME_FIELD = "secretName";
	public static final String NONCE_ID = "nonce-id";
	public static final String MESSAGE_FIELD = "message";
	public static final String Ex_COMMITMENTS = "ex_";
	public static final String Ey_COMMITMENTS = "ey_";
	public static final String Dx_COMMITMENTS = "dx_";
	public static final String Dy_COMMITMENTS = "dy_";

	// Fields
	private final AccessEnforcement accessEnforcement;
	private final ConcurrentMap<String, ApvssShareholder> shareholders;
	private final ConcurrentMap<UUID, NonceCommitment> nonceCommitments;

	public SchnorrSignHandler(final KeyLoader clientKeys, final AccessEnforcement accessEnforcement,
			final ConcurrentMap<String, ApvssShareholder> shareholders,
			ConcurrentHashMap<UUID, NonceCommitment> nonceCommitments) {
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

		// Extract message from request
		final String message = HttpRequestProcessor.getParameterValue(params, MESSAGE_FIELD);
		if (message == null) {
			throw new BadRequestException();
		}
		byte[] messageBytes;
		try {
			messageBytes = HexUtil.hexToBin(message);
		} catch (DecoderException e) {
			throw new BadRequestException();
		}


		// Obtain the commitments (B)
		final SortedMap<BigInteger, EcPoint> eCommitments = new TreeMap<>();
		final SortedMap<BigInteger, EcPoint> dCommitments = new TreeMap<>();
		for (int i = 1; i <= shareholder.getN(); i++) {
			final String exStrI = HttpRequestProcessor.getParameterValue(params, Ex_COMMITMENTS + i);
			final String eyStrI = HttpRequestProcessor.getParameterValue(params, Ey_COMMITMENTS + i);
			final String dxStrI = HttpRequestProcessor.getParameterValue(params, Dx_COMMITMENTS + i);
			final String dyStrI = HttpRequestProcessor.getParameterValue(params, Dy_COMMITMENTS + i);
			if ((exStrI != null) && (eyStrI != null) && (dxStrI != null) && (dyStrI != null)) {

				final EcPoint eCommitment = new EcPoint(new BigInteger(exStrI), new BigInteger(eyStrI));
				final EcPoint dCommitment = new EcPoint(new BigInteger(dxStrI), new BigInteger(dyStrI));

				// Ensure the resulting point exists on the curve
				if (!CommonConfiguration.CURVE.isPointOnCurve(eCommitment)) {
					throw new BadRequestException();
				}
				if (!CommonConfiguration.CURVE.isPointOnCurve(dCommitment)) {
					throw new BadRequestException();
				}

				eCommitments.put(BigInteger.valueOf(i), eCommitment);
				dCommitments.put(BigInteger.valueOf(i), dCommitment);
			}
		}

		if (!eCommitments.containsKey(BigInteger.valueOf(shareholder.getIndex()))) {
			// We were given a request for a signing operation we are not part of
			throw new BadRequestException();
		}

		// Ensure the secret is of the supported type
		if (!(SharingType.PEDERSEN_DKG.equals(shareholder.getSharingType())
				|| SharingType.FELDMAN_DKG.equals(shareholder.getSharingType()))) {
			throw new BadRequestException();
		}

		// Get the cached nonce, we remove it because it should only be used once
		final NonceCommitment ourCommitment = this.nonceCommitments.remove(nonceUUID);

		// Do processing
		final long startTime = System.nanoTime();
		final BigInteger signatureResponse = doSigning(shareholder, eCommitments, dCommitments, messageBytes,
				ourCommitment);
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

		obj.put("share", signatureResponse.toString());

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

	private BigInteger doSigning(final ApvssShareholder shareholder, final SortedMap<BigInteger, EcPoint> eCommitments,
			final SortedMap<BigInteger, EcPoint> dCommitments, final byte[] messageBytes,
			final NonceCommitment ourCommitment) throws NotFoundException, IOException {

		final BigInteger modulus =  CommonConfiguration.CURVE.getR();
		
		// Our nonce values
		final BigInteger ei = ourCommitment.getE();
		final BigInteger di = ourCommitment.getD();

		MessageDigest md;
		try {
			md = MessageDigest.getInstance("SHA-512");
		} catch (NoSuchAlgorithmException e) {
			throw new IOException();
		}
		
		if ((shareholder.getSecretPublicKey() == null) || (shareholder.getShare1() == null)) {
			throw new NotFoundException();
		} else {
			// Do FROST-based threshold Schnorr Signature calculation (
			// https://eprint.iacr.org/2020/852.pdf )
			
			// Our share of the private key
			final int myIndex = shareholder.getIndex();
			final BigInteger si = shareholder.getShare1().getY();
			final EcPoint secretPublicKey = shareholder.getSecretPublicKey();

			// Serialize the commitments (B)
			byte[] combinedString = messageBytes.clone();
			for (final BigInteger index : eCommitments.keySet()) {
				byte[] tuple = Parse.concatenate(index, eCommitments.get(index).getX(), eCommitments.get(index).getY(), dCommitments.get(index).getX(), dCommitments.get(index).getY());
				combinedString = Parse.concatenate(combinedString, tuple);
			}
			
			// Compute R from multiplying each Ri
			EcPoint R = EcPoint.pointAtInfinity;
			for (final BigInteger index : eCommitments.keySet()) {
				
				final EcPoint Di = new EcPoint(dCommitments.get(index).getX(), dCommitments.get(index).getY());
				
				final EcPoint Ei = new EcPoint(eCommitments.get(index).getX(), eCommitments.get(index).getY());
				final BigInteger Pi = new BigInteger(1, md.digest(Parse.concatenate(index.toByteArray(), combinedString))).mod(modulus);
				
				final EcPoint EiPi = CommonConfiguration.CURVE.multiply(Ei, Pi);
				
				final EcPoint Ri = CommonConfiguration.CURVE.addPoints(Di, EiPi);
				
				// Sum up the Ris
				R = CommonConfiguration.CURVE.addPoints(R, Ri);
			}
			
			
			// Compute challenge c = H(R, Y, m)
			byte[] challenge = Parse.concatenate(Parse.concatenate(R), Parse.concatenate(secretPublicKey), messageBytes);
			final BigInteger c = new BigInteger(1, md.digest(challenge));
			
			// Compute our share of the signature zi = di + ei*pi + Li
			final BigInteger pi = new BigInteger(1, md.digest(Parse.concatenate(BigInteger.valueOf(myIndex).toByteArray(), combinedString))).mod(modulus);

			final BigInteger coefficient = Polynomials.computeLagrange(eCommitments.keySet().toArray(new BigInteger[eCommitments.size()]), BigInteger.valueOf(myIndex), modulus);
			
			final BigInteger zi = ((di.add(ei.multiply(pi))).add(coefficient.multiply(si).multiply(c))).mod(modulus);
	
			
			return zi;
		}

	}

}