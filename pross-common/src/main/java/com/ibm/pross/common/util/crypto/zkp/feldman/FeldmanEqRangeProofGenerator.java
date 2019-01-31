package com.ibm.pross.common.util.crypto.zkp.feldman;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import com.ibm.pross.common.CommonConfiguration;
import com.ibm.pross.common.util.Exponentiation;
import com.ibm.pross.common.util.RandomNumberGenerator;
import com.ibm.pross.common.util.crypto.ecc.EcCurve;
import com.ibm.pross.common.util.crypto.ecc.EcPoint;
import com.ibm.pross.common.util.crypto.paillier.PaillierCipher;
import com.ibm.pross.common.util.crypto.paillier.PaillierPublicKey;
import com.ibm.pross.common.util.serialization.Parse;

public class FeldmanEqRangeProofGenerator {

	// Group Constants
	public static final EcCurve curve = CommonConfiguration.CURVE;
	public static final EcPoint g = CommonConfiguration.g;
	public static final EcPoint h = CommonConfiguration.h;

	// Used to compute c in ZKP
	public static final String HASH_ALGORITHM = CommonConfiguration.HASH_ALGORITHM;

	// Question: What are two security parameters k and l?
	public final static int k = 128;
	public static final int l = 128;
	public static final BigInteger Z = BigInteger.ONE.shiftLeft(k + l + 1).multiply(curve.getR());

	// Question: What is t?
	public static final int t = k;
	public static final BigInteger T = BigInteger.ONE.shiftLeft(t);

	/**
	 * <pre>
	 * Prove EqRangeZK(E, S) in zero knowledge:
	 * 
	 * The relationship of E = Enc(x, r1) S = g^x * h^r2
	 * 
	 * Prove knowledge of x, r1, r2 satisfying both of the above equations where E
	 * is a Paillier encryption and S is a Pedersen commitment.
	 * 
	 * @param publicKey
	 *            The public encryption key used to encrypt "x" under the Paillier
	 *            scheme
	 * @param x
	 *            The encrypted integer, also the exponent of g
	 * @param r1
	 *            A random integer used to obfuscate the Paillier encryption
	 * @param r2
	 *            When S is a Pedersen commitment, r2 is equal to "s"
	 * @param E
	 *            The encryption of x under the public key for random factor r1
	 * @param S
	 *            The Pedersen commitment g^x * h^s
	 * @return A proof of the relationship between the ciphertext and the Pedersen
	 *         commitment
	 */
	public static FeldmanEqRangeProof generate(final PaillierPublicKey publicKey, final BigInteger x, final BigInteger r1,
			final BigInteger r2, final BigInteger E, final EcPoint S) {

		// Get public key parameters
		final BigInteger n = publicKey.getN();
		final BigInteger nSquared = publicKey.getNSquared();

		// Prove knowledge
		final BigInteger alpha = RandomNumberGenerator.generateRandomInteger(Z);
		final BigInteger a = RandomNumberGenerator.generateRandomCoprimeInRange(n);
		final BigInteger b = RandomNumberGenerator.generateRandomPositiveInteger(curve.getR());

		final BigInteger E1 = PaillierCipher.encrypt(publicKey, alpha, a);
		final EcPoint S1 = curve.addPoints(curve.multiply(g, alpha), curve.multiply(h, b));

		// Compute c = H(E1, S1, E, S)
		final BigInteger c = hashParameters(E1, S1, E, S);

		final BigInteger z = alpha.add(c.multiply(x)); // z = alpha + c*x
		final BigInteger z1 = (a.multiply(Exponentiation.modPow(r1, c, nSquared))).mod(nSquared); // z1 = a * r1^c % n^2
		final BigInteger z2 = b.add(c.multiply(r2)); // z2 = b + c*r2

		// Shouldn't send c, right? Should send E and S?
		return new FeldmanEqRangeProof(E1, S1, z, z1, z2);
	}

	public static BigInteger hashParameters(final BigInteger E1, final EcPoint S1, final BigInteger E,
			final EcPoint S) {
		// Compute c = H(E1, S1, E, S)
		final byte[] input = Parse.concatenate(E1, S1.getX(), E, S.getX());
		final MessageDigest digest;
		try {
			digest = MessageDigest.getInstance(HASH_ALGORITHM);
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException("Should not happen");
		}
		return new BigInteger(1, digest.digest(input)).mod(T);
	}

}
