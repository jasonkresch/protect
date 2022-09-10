package com.ibm.pross.common.util.crypto.schnorr;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.util.Collection;
import java.util.SortedMap;
import java.util.SortedSet;
import java.util.TreeMap;
import java.util.TreeSet;

import com.ibm.pross.common.config.CommonConfiguration;
import com.ibm.pross.common.util.crypto.ecc.EcCurve;
import com.ibm.pross.common.util.crypto.ecc.EcPoint;
import com.ibm.pross.common.util.serialization.Parse;
import com.ibm.pross.common.util.shamir.Polynomials;

/**
 * Utility functions for FROST and Schnorr threshold signatures
 * 
 * @return
 */
public class SchnorrUtil {

	final public static EcCurve CURVE = CommonConfiguration.CURVE;
	final public static BigInteger MOD = CURVE.getR();
	final public static EcPoint G = CommonConfiguration.g;

	/**
	 * Sort a collection of nonce commitments by their participant index
	 * 
	 * @param nonceCommitments
	 * @return
	 */
	public static SortedSet<NonceCommitment> sortNonceCommitments(final Collection<NonceCommitment> nonceCommitments) {
		SortedSet<NonceCommitment> sortedNonceCommitments = new TreeSet<>(nonceCommitments);
		return sortedNonceCommitments;
	}

	/**
	 * Creates map of participant index to each nonce commitment
	 * 
	 * @param nonceCommitments
	 * @return
	 */
	public static SortedMap<BigInteger, NonceCommitment> mapNonceCommitments(
			final Collection<NonceCommitment> nonceCommitments) {
		// Sort the nonce commitments by participant index
		final SortedSet<NonceCommitment> sortedNonceCommitments = sortNonceCommitments(nonceCommitments);

		// Create a map of participant index to nonce commitment
		final SortedMap<BigInteger, NonceCommitment> nonceCommitmentMap = new TreeMap<>();
		for (NonceCommitment nonceCommitment : sortedNonceCommitments) {
			nonceCommitmentMap.put(BigInteger.valueOf(nonceCommitment.getParticipantIndex()), nonceCommitment);
		}
		return nonceCommitmentMap;
	}

	/**
	 * Create array of participant indices from map
	 * 
	 * @param nonceCommitmentMap
	 * @return
	 */
	public static BigInteger[] getParticipantIndices(final SortedMap<BigInteger, NonceCommitment> nonceCommitmentMap) {
		return nonceCommitmentMap.keySet().toArray(new BigInteger[nonceCommitmentMap.size()]);
	}

	/**
	 * Compute Lagrange coefficient for the given set of participants and
	 * participant index
	 * 
	 * @param participantIndices
	 * @param participantIndex
	 * @return
	 */
	public static BigInteger computeLagrangeCoefficient(final BigInteger[] participantIndices,
			final BigInteger participantIndex) {
		return Polynomials.computeLagrange(participantIndices, participantIndex, MOD);
	}

	/**
	 * Compute string "B" as defined in ( https://eprint.iacr.org/2020/852.pdf )
	 * 
	 * @param nonceCommitmentMap
	 * @return
	 */
	public static byte[] serializeNonceCommitments(final SortedMap<BigInteger, NonceCommitment> nonceCommitmentMap) {
		// Serialize an ordered set of Tuples of (i, Di, Ei)
		byte[] bString = new byte[0];
		for (final BigInteger participantIndex : nonceCommitmentMap.keySet()) {
			final NonceCommitment commitment = nonceCommitmentMap.get(participantIndex);

			byte[] participantIndexBytes = participantIndex.toByteArray();
			byte[] tuple = Parse.concatenate(participantIndexBytes,
					Parse.concatenate(commitment.getCommitmentD(), commitment.getCommitmentE()));

			// Append the tuple to the combined string
			bString = Parse.concatenate(bString, tuple);
		}

		return bString;
	}

	/**
	 * Perform a SHA-512 digest on input
	 * 
	 * @param input
	 * @return
	 */
	public static byte[] SHA512Hash(byte[] input) {
		try {
			final MessageDigest md = MessageDigest.getInstance("SHA-512");
			return md.digest(input);
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException(e);
		}
	}

	/**
	 * Compure intermediate R_i values
	 * 
	 * @param nonceCommitmentMap
	 * @param combinedString
	 * @return
	 */
	public static SortedMap<BigInteger, EcPoint> comptuteRValues(
			final SortedMap<BigInteger, NonceCommitment> nonceCommitmentMap, final byte[] combinedString) {
		// Create map of participant index to the corresponding R_i values
		final SortedMap<BigInteger, EcPoint> rValues = new TreeMap<>();

		for (final BigInteger participantIndex : nonceCommitmentMap.keySet()) {
			final NonceCommitment commitment = nonceCommitmentMap.get(participantIndex);

			byte[] participantIndexBytes = participantIndex.toByteArray();

			final EcPoint Di = commitment.getCommitmentD();
			final EcPoint Ei = commitment.getCommitmentE();
			final BigInteger Pi = new BigInteger(1,
					SHA512Hash(Parse.concatenate(participantIndexBytes, combinedString))).mod(MOD);

			final EcPoint EiPi = CURVE.multiply(Ei, Pi);

			final EcPoint Ri = CURVE.addPoints(Di, EiPi);
			rValues.put(participantIndex, Ri);
		}

		return rValues;
	}

	/**
	 * Sum a collection of EC points
	 * 
	 * @param ecPoints
	 * @return
	 */
	public static EcPoint sumEcPoints(final Collection<EcPoint> ecPoints) {
		EcPoint sum = EcPoint.pointAtInfinity;
		for (final EcPoint point : ecPoints) {
			sum = CommonConfiguration.CURVE.addPoints(sum, point);
		}
		return sum;
	}

	/**
	 * Sum a collection of big integers
	 * 
	 * @param nums
	 * @return
	 */
	public static BigInteger modSumNumbers(final Collection<BigInteger> nums) {
		BigInteger sum = BigInteger.ZERO;
		for (final BigInteger num : nums) {
			sum = sum.add(num).mod(MOD);
		}
		return sum;
	}

	/**
	 * Compute challenge as hash over R, public key, and message
	 * 
	 * @param R
	 * @param publicKey
	 * @param message
	 * @return
	 */
	public static BigInteger computeChallenge(final EcPoint R, final EcPoint publicKey, final byte[] message) {
		// Compute challenge c = H(R, Y, m)
		byte[] challenge = Parse.concatenate(Parse.concatenate(R), Parse.concatenate(publicKey), message);
		final BigInteger challengeNum = (new BigInteger(1, SHA512Hash(challenge))).mod(MOD);
		return challengeNum;
	}

	/**
	 * Compute a participant's contribution to a threshold signing operation
	 * 
	 * @param privateNonceCommitment
	 * @param privateKey
	 * @param combinedString
	 * @param participantIndices
	 * @param challenge
	 * @return
	 */
	public static BigInteger computeSignatureShare(final NonceCommitment privateNonceCommitment,
			final BigInteger privateKey, final byte[] combinedString, final BigInteger[] participantIndices,
			final BigInteger challenge) {
		final BigInteger participantIndex = BigInteger.valueOf(privateNonceCommitment.getParticipantIndex());
		final byte[] participantIndexBytes = participantIndex.toByteArray();

		final BigInteger si = privateKey;
		final BigInteger di = privateNonceCommitment.getNonceD();
		final BigInteger ei = privateNonceCommitment.getNonceE();
		final BigInteger pi = new BigInteger(1, SHA512Hash(Parse.concatenate(participantIndexBytes, combinedString)))
				.mod(MOD);

		final BigInteger l = Polynomials.computeLagrange(participantIndices, participantIndex, MOD);
		final BigInteger c = challenge;

		final BigInteger zi = ((di.add(ei.multiply(pi))).add(l.multiply(si).multiply(c))).mod(MOD);

		return zi;
	}

	/**
	 * Verify if a contribution to a threshold signature calculation is valid
	 * 
	 * @param participantIndex
	 * @param participantIndices
	 * @param shareholderPublicKey
	 * @param signatureShare
	 * @param challenge
	 * @param Ri
	 * @throws SignatureException
	 */
	public static void verifySignatureShare(final BigInteger participantIndex, final BigInteger[] participantIndices,
			final EcPoint shareholderPublicKey, final BigInteger signatureShare, final BigInteger challenge,
			final EcPoint Ri) throws SignatureException {
		
		// Compute Lagrange co-efficient
		final BigInteger l = Polynomials.computeLagrange(participantIndices, participantIndex, MOD);

		// Validate signature Share
		final EcPoint gZ = CURVE.multiply(G, signatureShare);
		final EcPoint Ycl = CURVE.multiply(shareholderPublicKey, challenge.multiply(l).mod(MOD));
		final EcPoint vgZ = CURVE.addPoints(Ri, Ycl);

		// Do comparison
		if (!gZ.equals(vgZ)) {
			throw new SignatureException("Contribution not valid!");
		}
	}

	/**
	 * Serialize the R and z components to form a final signature
	 * 
	 * @param R
	 * @param z
	 * @return
	 */
	public static byte[] composeSignature(final EcPoint R, final BigInteger z) {
		return Parse.concatenate(Parse.concatenate(R), Parse.concatenate(z));
	}
}
