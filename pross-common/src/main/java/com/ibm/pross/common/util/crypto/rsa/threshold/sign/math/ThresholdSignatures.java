package com.ibm.pross.common.util.crypto.rsa.threshold.sign.math;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.List;

import com.ibm.pross.common.CommonConfiguration;
import com.ibm.pross.common.util.Exponentiation;
import com.ibm.pross.common.util.RandomNumberGenerator;
import com.ibm.pross.common.util.crypto.rsa.threshold.sign.data.SignatureResponse;
import com.ibm.pross.common.util.crypto.rsa.threshold.sign.data.SignatureShareProof;
import com.ibm.pross.common.util.crypto.rsa.threshold.sign.exceptions.BadArgumentException;
import com.ibm.pross.common.util.crypto.rsa.threshold.sign.server.ServerConfiguration;
import com.ibm.pross.common.util.crypto.rsa.threshold.sign.server.ServerPublicConfiguration;
import com.ibm.pross.common.util.serialization.Parse;
import com.ibm.pross.common.util.shamir.Polynomials;
import com.ibm.pross.common.util.shamir.ShamirShare;

/**
 * Implements functions of "Practical Threshold Signatures" which includes: -
 * Generating signature shares and proofs of correctness - Verifying signature
 * shares with their proofs - Combining signature shares to recover a signature
 * 
 * @see http://www.iacr.org/archive/eurocrypt2000/1807/18070209-new.pdf
 */
public class ThresholdSignatures {

	// Useful
	public static final BigInteger TWO = BigInteger.valueOf(2);

	// Hash length (bits)
	public static final int HASH_LEN = 256;
	public static final BigInteger HASH_MOD = TWO.pow(HASH_LEN);

	/**
	 * Produce a Signature Share and a proof of its correctness (contained in a
	 * SignatureShareProof object). This requires the server private information.
	 * 
	 * @param inputMessage
	 * @param serverConfig
	 * @return
	 */
	public static SignatureResponse produceSignatureResponse(final BigInteger inputMessage,
			final ServerConfiguration serverConfig) {

		// Extract public configuration and share
		final ServerPublicConfiguration publicConfig = serverConfig.getServerPublicConfiguration();
		final ShamirShare share = serverConfig.getShare();

		// Compute signature share
		final BigInteger n = publicConfig.getN();
		final int serverCount = publicConfig.getServerCount();
		final BigInteger delta = Polynomials.factorial(BigInteger.valueOf(serverCount));
		final BigInteger secretShare = share.getY();
		final BigInteger exponent = TWO.multiply(delta).multiply(secretShare);
		final BigInteger signatureShare = Exponentiation.modPow(inputMessage, exponent, n);

		// Compute verification proof
		final BigInteger v = publicConfig.getV();
		final BigInteger index = share.getX();
		final BigInteger vk = publicConfig.getVerificationKeys()[index.intValue() - 1];
		final BigInteger mToFourD = Exponentiation.modPow(inputMessage, BigInteger.valueOf(4).multiply(delta), n);
		final BigInteger r = RandomNumberGenerator.generateRandomInteger(n.bitLength() + 2 * HASH_LEN);
		final BigInteger vPrime = Exponentiation.modPow(v, r, n);
		final BigInteger xPrime = Exponentiation.modPow(mToFourD, r, n);
		final BigInteger shareSquared = Exponentiation.modPow(signatureShare, TWO, n);

		final byte[] verificationString = Parse.concatenate(v, mToFourD, vk, shareSquared, vPrime, xPrime);
		final BigInteger c = hashToInteger(verificationString, TWO.pow(HASH_LEN));
		final BigInteger z = secretShare.multiply(c).add(r);
		final SignatureShareProof signatureShareProof = new SignatureShareProof(c, z);

		return new SignatureResponse(index, signatureShare, signatureShareProof);
	}

	/**
	 * Validate a SignatureTriplet is consistent with public verification keys and
	 * the input message
	 * 
	 * @param inputMessage
	 * @param signatureResponse
	 * @param configuration
	 * @return
	 * @throws BadArgumentException
	 */
	public static boolean validateSignatureResponse(final BigInteger inputMessage,
			final SignatureResponse signatureResponse, final ServerPublicConfiguration configuration)
			throws BadArgumentException {

		// Extract configuration items
		final BigInteger n = configuration.getN();
		final BigInteger v = configuration.getV();
		final BigInteger[] verificationKeys = configuration.getVerificationKeys();
		final int serverCount = configuration.getServerCount();

		// Extract elements from returned signature triplet
		final BigInteger index = signatureResponse.getServerIndex();
		final BigInteger signatureShare = signatureResponse.getSignatureShare();
		final BigInteger z = signatureResponse.getSignatureShareProof().getZ();
		final BigInteger c = signatureResponse.getSignatureShareProof().getC();

		// Perform verification
		final BigInteger vToZ = Exponentiation.modPow(v, z, n);
		final int keyIndex = index.intValue() - 1;
		if ((keyIndex < 0) || (keyIndex >= verificationKeys.length)) {
			return false;
		}
		final BigInteger vk = verificationKeys[keyIndex];
		final BigInteger invVerificationKey = Exponentiation.modInverse(vk, n);
		final BigInteger invVkToC = Exponentiation.modPow(invVerificationKey, c, n);
		final BigInteger vTerms = vToZ.multiply(invVkToC).mod(n);

		final BigInteger delta = Polynomials.factorial(BigInteger.valueOf(serverCount));
		final BigInteger mToFourD = Exponentiation.modPow(inputMessage, BigInteger.valueOf(4).multiply(delta), n);
		final BigInteger xToZ = Exponentiation.modPow(mToFourD, z, n);
		final BigInteger invShare = Exponentiation.modInverse(signatureShare, n);
		final BigInteger invShareToTwoC = Exponentiation.modPow(invShare, TWO.multiply(c), n);
		final BigInteger xTerms = xToZ.multiply(invShareToTwoC).mod(n);

		final BigInteger shareSquared = Exponentiation.modPow(signatureShare, TWO, n);

		final byte[] verificationString = Parse.concatenate(v, mToFourD, vk, shareSquared, vTerms, xTerms);
		final BigInteger recomputedC = hashToInteger(verificationString, HASH_MOD);

		if (recomputedC.equals(c)) {
			return true;
		} else {
			return false;
		}
	}

	private static BigInteger hashToInteger(final byte[] input, final BigInteger modulus) {
		try {
			byte[] hashed = MessageDigest.getInstance(CommonConfiguration.HASH_ALGORITHM).digest(input);
			return (new BigInteger(1, hashed)).mod(modulus);
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException(e);
		}

	}

	/**
	 * Combine a threshold number of signature shares to recover the signature of
	 * the inputMessage
	 * 
	 * @param inputMessage       The message to be signed
	 * @param signatureResponses A list of signature responses from different
	 *                           servers for the same input message
	 * @param configuration      Public configuration information shared by all
	 *                           servers
	 * @return The digital signature of the input message
	 * @throws BadArgumentException
	 */
	public static BigInteger recoverSignature(final BigInteger inputMessage,
			final List<SignatureResponse> signatureResponses, final ServerPublicConfiguration configuration)
			throws BadArgumentException {

		// Extract values from configuration
		final BigInteger n = configuration.getN();
		final BigInteger e = configuration.getE();
		final int serverCount = configuration.getServerCount();
		final BigInteger delta = Polynomials.factorial(BigInteger.valueOf(serverCount));
		final int threshold = configuration.getThreshold();

		// Determine coordinates
		final BigInteger[] xCoords = new BigInteger[threshold];
		for (int i = 0; i < threshold; i++) {
			final SignatureResponse signatureResponse = signatureResponses.get(i);
			xCoords[i] = signatureResponse.getServerIndex();
		}

		// Interpolate polynomial
		System.out.print(" " + Arrays.toString(xCoords));
		BigInteger w = BigInteger.ONE;
		for (int i = 0; i < threshold; i++) {
			final SignatureResponse signatureResponse = signatureResponses.get(i);

			final BigInteger j = signatureResponse.getServerIndex();
			final BigInteger signatureShare = signatureResponse.getSignatureShare();
			final BigInteger L_ij = Polynomials.interpolateNoModulus(xCoords, delta, BigInteger.ZERO, j);

			w = w.multiply(Exponentiation.modPow(signatureShare, TWO.multiply(L_ij), n));
		}

		// Use Extended Euclidean Algorithm to solve for the signature
		final BigInteger ePrime = delta.multiply(delta).multiply(BigInteger.valueOf(4)); // 4*D*D
		final GcdTriplet gcdTriplet = extendedGreatestCommonDivisor(ePrime, e);
		final BigInteger a = gcdTriplet.getX();
		final BigInteger b = gcdTriplet.getY();

		return Exponentiation.modPow(w, a, n).multiply(Exponentiation.modPow(inputMessage, b, n)).mod(n);
	}

	/**
	 * Represents a triplet of numbers returned by the Extended Euclidean Algorithm
	 */
	protected static class GcdTriplet {

		private final BigInteger g;
		private final BigInteger x;
		private final BigInteger y;

		public GcdTriplet(final BigInteger g, final BigInteger x, final BigInteger y) {
			this.g = g;
			this.x = x;
			this.y = y;
		}

		/**
		 * Represents gcd(a, b)
		 * 
		 * @return
		 */
		public BigInteger getG() {
			return g;
		}

		/**
		 * Represents the co-efficient of b in the identity: ax + by = gcd(a, b)
		 * 
		 * @return
		 */
		public BigInteger getY() {
			return y;
		}

		/**
		 * Represents the co-efficient of b in the identity: ax + by = gcd(a, b)
		 * 
		 * @return
		 */
		public BigInteger getX() {
			return x;
		}

	}

	/**
	 * Returns a triplet representing the greatest common divisor between a and b
	 * (g), as well as the coefficients x and y that satisfy Bézout's identity: ax +
	 * by = gcd(a, b)
	 * 
	 * @param a
	 * @param b
	 * @return (g, x, y)
	 */
	protected static GcdTriplet extendedGreatestCommonDivisor(BigInteger a, BigInteger b) {
		if (a.equals(BigInteger.ZERO)) {
			return new GcdTriplet(b, BigInteger.ZERO, BigInteger.ONE);
		} else {
			GcdTriplet t = extendedGreatestCommonDivisor(b.mod(a), a);
			BigInteger g = t.getG();
			BigInteger x = t.getX();
			BigInteger y = t.getY();
			return new GcdTriplet(g, y.subtract(b.divide(a).multiply(x)), x);
		}
	}

}
