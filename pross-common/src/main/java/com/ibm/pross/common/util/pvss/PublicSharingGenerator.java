package com.ibm.pross.common.util.pvss;

import java.math.BigInteger;

import com.ibm.pross.common.CommonConfiguration;
import com.ibm.pross.common.util.RandomNumberGenerator;
import com.ibm.pross.common.util.crypto.ecc.EcCurve;
import com.ibm.pross.common.util.crypto.ecc.EcPoint;
import com.ibm.pross.common.util.crypto.paillier.PaillierCipher;
import com.ibm.pross.common.util.crypto.paillier.PaillierPublicKey;
import com.ibm.pross.common.util.crypto.zkp.pedersen.PedersenEqRangeProof;
import com.ibm.pross.common.util.crypto.zkp.pedersen.PedersenEqRangeProofGenerator;
import com.ibm.pross.common.util.shamir.Shamir;
import com.ibm.pross.common.util.shamir.ShamirShare;

public class PublicSharingGenerator {

	// Group Constants
	public static final EcCurve curve = CommonConfiguration.CURVE;
	public static final EcPoint g = CommonConfiguration.g;
	public static final EcPoint h = CommonConfiguration.h;

	private final int numShares; // n
	private final int threshold; // t

	public PublicSharingGenerator(final int numShares, final int threshold) {
		this.numShares = numShares;
		this.threshold = threshold;
	}

	public PublicSharing shareRandomSecret(final PaillierPublicKey[] shareholderKeys) {
		final BigInteger secret = RandomNumberGenerator.generateRandomInteger(curve.getR());
		return shareSecret(secret, shareholderKeys);
	}
	
	public PublicSharing shareSecret(final BigInteger secret, final PaillierPublicKey[] shareholderKeys) {
		final BigInteger randomness = RandomNumberGenerator.generateRandomInteger(curve.getR());
		return shareSecretAndRandomness(secret, randomness, shareholderKeys);
	}

	public PublicSharing shareSecretAndRandomness(final BigInteger secret, final BigInteger randomness, final PaillierPublicKey[] shareholderKeys) {
		// The secret is held in the first element of the array: polynomial[0]
		final BigInteger[] polynomial1 = Shamir.generateCoefficients(this.threshold);
		polynomial1[0] = secret;

		// The second polynomial is to blind information in the commitment
		final BigInteger[] polynomial2 = Shamir.generateCoefficients(this.threshold);
		polynomial2[0] = randomness;

		// Compute shares for i = 1 to N
		final ShamirShare[] shares1 = Shamir.generateShares(polynomial1, this.numShares);
		final ShamirShare[] shares2 = Shamir.generateShares(polynomial2, this.numShares);

		// Create Pedersen commitments: C_ik
		final EcPoint[] gA = Shamir.generateFeldmanValues(polynomial1, g);
		final EcPoint[] hB = Shamir.generateFeldmanValues(polynomial2, h);
		final EcPoint[] pedersenCommitments = new EcPoint[this.threshold];
		for (int i = 0; i < this.threshold; i++) {
			pedersenCommitments[i] = curve.addPoints(gA[i], hB[i]);
		}

		// Encrypt the shares and create the zero knowledge proofs of correctness
		final BigInteger[] encryptedShares1 = new BigInteger[this.numShares];
		final BigInteger[] encryptedShares2 = new BigInteger[this.numShares];
		final PedersenEqRangeProof[] proofs = new PedersenEqRangeProof[this.numShares];
		for (int i = 0; i < this.numShares; i++) {

			// Use shares
			final BigInteger share1 = shares1[i].getY();
			final BigInteger share2 = shares2[i].getY();

			// Encrypt shares
			final PaillierPublicKey encryptionKey = shareholderKeys[i];
			final BigInteger r1 = RandomNumberGenerator.generateRandomCoprimeInRange(encryptionKey.getN());
			final BigInteger r2 = RandomNumberGenerator.generateRandomCoprimeInRange(encryptionKey.getN());
			encryptedShares1[i] = PaillierCipher.encrypt(encryptionKey, share1, r1);
			encryptedShares2[i] = PaillierCipher.encrypt(encryptionKey, share2, r2);

			// Produce proof
			final EcPoint shareCommmitment = interpolatePedersonCommitments(shares1[i].getX(), pedersenCommitments);
			proofs[i] = PedersenEqRangeProofGenerator.generate(encryptionKey, share1, share2, r1, r2, encryptedShares1[i],
					encryptedShares2[i], shareCommmitment);
		}

		return new PublicSharing(pedersenCommitments, encryptedShares1, encryptedShares2, proofs);
	}

	public static EcPoint interpolatePedersonCommitments(final BigInteger position, final EcPoint[] commitments) {

		// Check that each point is on the curve and is not a point at infinity or has a
		// null x coordinate
		for (final EcPoint point : commitments) {
			if ((!curve.isPointOnCurve(point)) || (EcPoint.pointAtInfinity.equals(point)) || (point.getX() == null)) {
				throw new IllegalArgumentException("Commitments are invalid");
			}
		}

		// Compute expected value of a commitment for a given share, from the
		// co-efficient commitments
		EcPoint sum = EcPoint.pointAtInfinity;
		for (int i = 0; i < commitments.length; i++) {
			final EcPoint term = curve.multiply(commitments[i], position.pow(i));
			sum = curve.addPoints(sum, term);
		}

		return sum;
	}

	public int getNumShares() {
		return numShares;
	}

	public int getThreshold() {
		return threshold;
	}

}
