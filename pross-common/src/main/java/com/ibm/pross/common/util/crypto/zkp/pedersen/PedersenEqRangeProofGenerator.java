package com.ibm.pross.common.util.crypto.zkp.pedersen;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import com.ibm.pross.common.config.CommonConfiguration;
import com.ibm.pross.common.util.Exponentiation;
import com.ibm.pross.common.util.RandomNumberGenerator;
import com.ibm.pross.common.util.crypto.ecc.EcCurve;
import com.ibm.pross.common.util.crypto.ecc.EcPoint;
import com.ibm.pross.common.util.crypto.paillier.PaillierCipher;
import com.ibm.pross.common.util.crypto.paillier.PaillierPublicKey;
import com.ibm.pross.common.util.serialization.Parse;

public class PedersenEqRangeProofGenerator {

	// Group Constants
	public static final EcCurve curve = CommonConfiguration.CURVE;
	public static final EcPoint g = CommonConfiguration.g;
	public static final EcPoint h = CommonConfiguration.h;

	// Used to compute c in ZKP
	public static final String HASH_ALGORITHM = CommonConfiguration.HASH_ALGORITHM;

	// Question: What are two security parameters k and l?
	public final static int k = 256;
	public static final BigInteger Z = BigInteger.ONE.shiftLeft(k + 1).multiply(curve.getR());
	public static final BigInteger T = BigInteger.ONE.shiftLeft(k);

	/**
	 * <pre>
	 * Prove EqRangeZK(Ea, Eb, S) in zero knowledge:
	 * 
	 * The relationship to be proven: Ea = Enc(a, r1); Eb = Enc(b, r2); S = g^a *
	 * h^b
	 * 
	 * Prove knowledge of a, b, r1, r2 satisfying both of the above equations where
	 * Ea is a Paillier encryption of a, Eb is a Paillier encryption of b, and S is
	 * a Pedersen commitment.
	 * 
	 * @param publicKey
	 *            The public encryption key used to encrypt a and b under the
	 *            Paillier scheme
	 * @param a
	 *            The first encrypted integer, also the exponent of g in the
	 *            commitment
	 * @param b
	 *            The second encrypted integer, also the exponent of h in the
	 *            commitment
	 * @param r1
	 *            A random integer used to obfuscate the Paillier encryption of a
	 * @param r2
	 *            A random integer used to obfuscate the Paillier encryption of b
	 * @param Ea
	 *            The encryption of a under the public key for random factor r1
	 * @param Eb
	 *            The encryption of b under the public key for random factor r2
	 * @param S
	 *            The Pedersen commitment S = (g^a * h^b)
	 * @return A proof of the relationship between the ciphertexts and the Pedersen
	 *         commitment, and knowledge of a, b, r1, r2 satisfying the relationshop
	 */
	public static PedersenEqRangeProof generate(final PaillierPublicKey publicKey, final BigInteger a,
			final BigInteger b, final BigInteger r1, final BigInteger r2, final BigInteger Ea, final BigInteger Eb,
			final EcPoint S) {

		// Get public key parameters
		final BigInteger n = publicKey.getN();
		final BigInteger nSquared = publicKey.getNSquared();

		/* Prove knowledge */

		// Chose integers in range of Z
		final BigInteger alpha = RandomNumberGenerator.generateRandomInteger(Z);
		final BigInteger beta = RandomNumberGenerator.generateRandomInteger(Z);

		// Chose blinding factors for encryption in range of n
		final BigInteger u1 = RandomNumberGenerator.generateRandomCoprimeInRange(n);
		final BigInteger u2 = RandomNumberGenerator.generateRandomCoprimeInRange(n);

		// Perform encryptions of alpha and beta
		final BigInteger Ealpha = PaillierCipher.encrypt(publicKey, alpha, u1);
		final BigInteger Ebeta = PaillierCipher.encrypt(publicKey, beta, u2);

		// Create commitment
		final EcPoint S1 = curve.addPoints(curve.multiply(g, alpha), curve.multiply(h, beta));

		// Compute c = H(Ealpha, Ebeta, S1, Ea, Eb, S)
		final BigInteger c = hashParameters(Ealpha, Ebeta, S1, Ea, Eb, S);

		final BigInteger z1 = alpha.add(c.multiply(a)); // z1 = alpha + c*a
		final BigInteger z2 = beta.add(c.multiply(b)); // z2 = beta + c*b
		final BigInteger e1 = (u1.multiply(Exponentiation.modPow(r1, c, nSquared))).mod(nSquared); // e1 = u1 * r1^c % n^2
		final BigInteger e2 = (u2.multiply(Exponentiation.modPow(r2, c, nSquared))).mod(nSquared); // e2 = u2 * r2^c % n^2
		
		// Proof = (Eα,Eβ,S1,c,z1,z2,e1,e2)
		return new PedersenEqRangeProof(Ealpha, Ebeta, S1, z1, z2, e1, e2);
	}

	public static BigInteger hashParameters(final BigInteger Ealpha, final BigInteger Ebeta, final EcPoint S1,
			final BigInteger Ea, final BigInteger Eb, final EcPoint S) {

		// Compute c = H(Ealpha, Ebeta, S1, Ea, Eb, S)
		final byte[] input = Parse.concatenate(Ealpha, Ebeta, S1.getX(), Ea, Eb, S.getX());
		final MessageDigest digest;
		try {
			digest = MessageDigest.getInstance(HASH_ALGORITHM);
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException("Should not happen");
		}
		return new BigInteger(1, digest.digest(input)).mod(T);
	}

}
