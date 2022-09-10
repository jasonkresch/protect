package com.ibm.pross.common.util.crypto.schnorr;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.util.Map.Entry;
import java.util.SortedMap;
import java.util.TreeMap;

import org.apache.commons.codec.Charsets;
import org.bouncycastle.util.Arrays;

import com.ibm.pross.common.config.CommonConfiguration;
import com.ibm.pross.common.util.RandomNumberGenerator;
import com.ibm.pross.common.util.crypto.ecc.EcCurve;
import com.ibm.pross.common.util.crypto.ecc.EcPoint;
import com.ibm.pross.common.util.serialization.Parse;
import com.ibm.pross.common.util.shamir.Polynomials;
import com.ibm.pross.common.util.shamir.Shamir;
import com.ibm.pross.common.util.shamir.ShamirShare;

public class SchnorrSignatures {

	private static byte[] sign1(final EcCurve curve, final MessageDigest md, final BigInteger privateKey,
			final EcPoint publicKey, byte[] message) {
		// Generate nonce
		final BigInteger fieldModulus = curve.getR();
		final BigInteger k = RandomNumberGenerator.generateRandomPositiveInteger(fieldModulus);

		// Calculate r = g^k
		final EcPoint r = curve.multiply(CommonConfiguration.g, k);

		// Compute e as hash(R, Y, m)
		byte[] challenge = Parse.concatenate(Parse.concatenate(r), Parse.concatenate(publicKey), message);
		BigInteger e = new BigInteger(1, md.digest(challenge));

		// Compute s = k - xe
		BigInteger s = (k.subtract(privateKey.multiply(e))).mod(fieldModulus);

		return Parse.concatenate(s, e);
	}

	private static void verifySchnorrSignature1(final EcCurve curve, final MessageDigest md, final EcPoint publicKey,
			byte[] message, byte[] signature) throws SignatureException {
		byte[][] sePair = Parse.splitArrays(signature);
		final BigInteger s = new BigInteger(1, sePair[0]);
		final BigInteger e = new BigInteger(1, sePair[1]);

		final EcPoint gS = curve.multiply(CommonConfiguration.g, s);
		final EcPoint yE = curve.multiply(publicKey, e);
		final EcPoint rv = curve.addPoints(gS, yE);

		byte[] challenge = Parse.concatenate(Parse.concatenate(rv), Parse.concatenate(publicKey), message);
		final BigInteger ev = new BigInteger(1, md.digest(challenge));

		if (Arrays.constantTimeAreEqual(e.toByteArray(), ev.toByteArray())) {
			// Valid signature
		} else {
			// Bad Signature!
			throw new SignatureException("Signature does not match!");
		}
	}

	public static byte[] sign(final EcCurve curve, final MessageDigest md, final BigInteger privateKey,
			final EcPoint publicKey, byte[] message) {
		// Generate nonce
		final BigInteger fieldModulus = curve.getR();
		final BigInteger k = RandomNumberGenerator.generateRandomPositiveInteger(fieldModulus);

		// Calculate r = g^k
		final EcPoint r = curve.multiply(CommonConfiguration.g, k);

		// Compute e as hash(R, Y, m)
		byte[] challenge = Parse.concatenate(Parse.concatenate(r), Parse.concatenate(publicKey), message);
		BigInteger c = new BigInteger(1, md.digest(challenge));

		// Compute z = k -+ sc
		BigInteger z = (k.add(privateKey.multiply(c))).mod(fieldModulus);

		return Parse.concatenate(Parse.concatenate(r), Parse.concatenate(z));
	}

	public static void verify(final EcCurve curve, final MessageDigest md, final EcPoint publicKey, byte[] message,
			byte[] signature) throws SignatureException {
		byte[][] sePair = Parse.splitArrays(signature);
		final byte[][] rParts = Parse.splitArrays(sePair[0]);
		EcPoint r = new EcPoint(new BigInteger(1, rParts[0]), new BigInteger(1, rParts[1]));
		final BigInteger z = new BigInteger(1, Parse.splitArrays(sePair[1])[0]);

		// Compute e as hash(R, Y, m)
		byte[] challenge = Parse.concatenate(Parse.concatenate(r), Parse.concatenate(publicKey), message);
		BigInteger c = new BigInteger(1, md.digest(challenge));

		final EcPoint gZ = curve.multiply(CommonConfiguration.g, z);
		final EcPoint yC = curve.multiply(publicKey, BigInteger.ZERO.subtract(c));
		final EcPoint rv = curve.addPoints(gZ, yC);

		if (r.equals(rv)) {
			// Valid signature
		} else {
			// Bad Signature!
			throw new SignatureException("Signature does not match!");
		}
	}

	public static void main(String[] args) throws NoSuchAlgorithmException, SignatureException {
		// Static fields
		final EcCurve curve = CommonConfiguration.CURVE;
		final BigInteger fieldModulus = curve.getR();

		final MessageDigest md = MessageDigest.getInstance("SHA-512");

		final BigInteger privateSigningKey = RandomNumberGenerator.generateRandomPositiveInteger(fieldModulus);
		final EcPoint publicVerificationKey = curve.multiply(CommonConfiguration.g, privateSigningKey);

		byte[] message = "Hello World!".getBytes(Charsets.UTF_8);
		byte[] signature = sign1(curve, md, privateSigningKey, publicVerificationKey, message);

		verifySchnorrSignature1(curve, md, publicVerificationKey, message, signature);

		System.out.println("Verified signature!");

		// verifySchnorrSignature1(curve, md, publicVerificationKey, "Wrong
		// message".getBytes(), signature);

		thresholdSchnorr();
	}

	public static void thresholdSchnorr() throws NoSuchAlgorithmException, SignatureException {

		final MessageDigest md = MessageDigest.getInstance("SHA-512");

		final int threshold = 3;
		final int numShares = 5;

		final BigInteger[] coefficients = Shamir.generateCoefficients(threshold);
		final ShamirShare[] shares = Shamir.generateShares(coefficients, numShares);

		final EcPoint[] feldmanValues = Shamir.generateFeldmanValues(coefficients, CommonConfiguration.g);
		final EcPoint[] shareholderPublicKeys = Shamir.computeSharePublicKeys(feldmanValues, numShares);

		// The main private/public key pair
		final EcPoint publicKey = Shamir.computeSharePublicKey(feldmanValues, 0);
		final BigInteger privateKey = coefficients[0];

		/****************************************************************************/

		// Everything is initialized, do sanity check withh public and private key

		byte[] message = "Hello World!".getBytes(Charsets.UTF_8);
		byte[] signature = sign(SchnorrUtil.CURVE, md, privateKey, publicKey, message);

		verify(SchnorrUtil.CURVE, md, publicKey, message, signature);
		System.out.println("Verified threshold signature 1!");

		/****************************************************************************/

		// Start the distributed signing by creating commitments

		final SortedMap<BigInteger, NonceCommitment> nonceCommitmentMap = new TreeMap<>();
		for (int i = 1; i < 5; i++) {
			nonceCommitmentMap.put(BigInteger.valueOf(i),
					NonceCommitment.generateNonceCommitment(SchnorrUtil.CURVE, i));
		}

		System.out.println(nonceCommitmentMap.keySet().toString());

		final BigInteger[] participantIndices = SchnorrUtil.getParticipantIndices(nonceCommitmentMap);
		for (final BigInteger participantIndex : nonceCommitmentMap.keySet()) {
			BigInteger coefficient = SchnorrUtil.computeLagrangeCoefficient(participantIndices, participantIndex);
			System.out.println(participantIndex.toString() + " " + coefficient.toString());
		}

		// Create M || B
		byte[] stringB = SchnorrUtil.serializeNonceCommitments(nonceCommitmentMap);
		byte[] combinedString = Parse.concatenate(message, stringB);

		// Compute R_i values
		final SortedMap<BigInteger, EcPoint> Ris = SchnorrUtil.comptuteRValues(nonceCommitmentMap, combinedString);

		// Compute R as sum of all the R_is
		final EcPoint R = SchnorrUtil.sumEcPoints(Ris.values());

		// Compute challenge c = H(R, Y, m)
		final BigInteger challenge = SchnorrUtil.computeChallenge(R, publicKey, message);

		// Compute each share of the signature zi = di + ei*pi + Li
		final SortedMap<BigInteger, BigInteger> shareContributions = new TreeMap<>();
		for (final NonceCommitment privateNonceCommitment : nonceCommitmentMap.values()) {

			final BigInteger participantPrivateKey = shares[privateNonceCommitment.getParticipantIndex() - 1].getY();

			final BigInteger zi = SchnorrUtil.computeSignatureShare(privateNonceCommitment, participantPrivateKey,
					combinedString, participantIndices, challenge);

			shareContributions.put(BigInteger.valueOf(privateNonceCommitment.getParticipantIndex()), zi);
		}

		System.out.println(shareContributions.toString());

		// Verify all the share contributions
		for (Entry<BigInteger, BigInteger> entry : shareContributions.entrySet()) {
			final BigInteger participantIndex = entry.getKey();
			final BigInteger signatureShare = entry.getValue();
			final EcPoint shareholderPublicKey = shareholderPublicKeys[participantIndex.intValue() - 1];
			final EcPoint Ri = Ris.get(participantIndex);

			SchnorrUtil.verifySignatureShare(participantIndex, participantIndices, shareholderPublicKey, signatureShare,
					challenge, Ri);
		}

		// Compute sum of all zs
		BigInteger sum = SchnorrUtil.modSumNumbers(shareContributions.values());

		// Serialize the signature
		final byte[] thresholdSig = SchnorrUtil.composeSignature(R, sum);

		verify(SchnorrUtil.CURVE, md, publicKey, message, thresholdSig);
		System.out.println("Verified threshold signature 2!");
	}

}
