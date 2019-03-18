package com.ibm.pross.common.util.crypto.zkp.feldman;

import static org.junit.Assert.fail;

import java.math.BigInteger;

import org.junit.Assert;
import org.junit.Test;

import com.ibm.pross.common.config.CommonConfiguration;
import com.ibm.pross.common.util.RandomNumberGenerator;
import com.ibm.pross.common.util.crypto.ecc.EcCurve;
import com.ibm.pross.common.util.crypto.ecc.EcPoint;
import com.ibm.pross.common.util.crypto.paillier.PaillierCipher;
import com.ibm.pross.common.util.crypto.paillier.PaillierKeyGenerator;
import com.ibm.pross.common.util.crypto.paillier.PaillierKeyPair;
import com.ibm.pross.common.util.crypto.paillier.PaillierPrivateKey;
import com.ibm.pross.common.util.crypto.paillier.PaillierPublicKey;


public class FeldmanEqRangeProofTest {

	public static final EcCurve curve = CommonConfiguration.CURVE;
	public static final EcPoint g = CommonConfiguration.g;
	public static final EcPoint h = CommonConfiguration.h;

	@Test
	public void testGenerate() {
		// Also implement negative test cases
		fail("Not yet implemented");
	}

	@Test
	public void testAll() {

		// Generate encryption key
		System.out.println("Generating key...");
		final PaillierKeyGenerator keyGenerator = new PaillierKeyGenerator(2048);
		long s1 = System.nanoTime();
		final PaillierKeyPair keyPair = keyGenerator.generate();
		long e1 = System.nanoTime();
		System.out.println("Done. Took: " + ((e1 - s1) / 1_000_000.0) + " ms");
		System.out.println();

		// Get public and private keys
		final PaillierPublicKey publicKey = keyPair.getPublicKey();
		final PaillierPrivateKey privateKey = keyPair.getPrivateKey();

		final BigInteger share = BigInteger.valueOf(12345);

		System.out.println("Encrypting share...");

		// Generate randomness: r
		final BigInteger n = publicKey.getN();

		// Warm up
		PaillierCipher.encrypt(publicKey, share);

		// Encrypt value
		long s2 = System.nanoTime();
		final BigInteger r1 = RandomNumberGenerator.generateRandomCoprimeInRange(n);
		final BigInteger E = PaillierCipher.encrypt(publicKey, share, r1);
		long e2 = System.nanoTime();
		System.out.println("Done. Took: " + ((e2 - s2) / 1_000_000.0) + " ms");
		System.out.println();

		// Create commitment
		System.out.println("Creating Pedersen commitment...");
		long s3 = System.nanoTime();
		final BigInteger r2 = RandomNumberGenerator.generateRandomPositiveInteger(curve.getR());
		final EcPoint S = curve.addPoints(curve.multiply(g, share), curve.multiply(h, r2));
		long e3 = System.nanoTime();
		System.out.println("Done. Took: " + ((e3 - s3) / 1_000_000.0) + " ms");
		System.out.println();

		// Generating zero knowledge proof
		System.out.println("Generating zero knowledge proof...");
		long s4 = System.nanoTime();
		final FeldmanEqRangeProof proof = FeldmanEqRangeProofGenerator.generate(publicKey, share, r1, r2, E, S);
		long e4 = System.nanoTime();
		System.out.println("Done. Took: " + ((e4 - s4) / 1_000_000.0) + " ms");
		System.out.println();

		// Print proof
		// System.out.println("Sizes: ");
		// System.out.println("E1: " + proof.getE1().toByteArray().length);
		// System.out.println("S1: " + proof.getS1().getX().toByteArray().length);
		// System.out.println("Z: " + proof.getZ().toByteArray().length);
		// System.out.println("Z1: " + proof.getZ1().toByteArray().length);
		// System.out.println("Z2: " + proof.getZ2().toByteArray().length);

		// Validate proof
		System.out.println("Verifying zero knowledge proof...");
		long s5 = System.nanoTime();
		final boolean valid = FeldmanEqRangeProofVerifier.isValid(proof, E, S, publicKey);
		long e5 = System.nanoTime();
		System.out.println("Done. Took: " + ((e5 - s5) / 1_000_000.0) + " ms");
		System.out.println("Proof is valid: " + valid);
		Assert.assertTrue(valid);
		System.out.println();

		// Validate decryption
		System.out.println("Decrypting share...");
		long s6 = System.nanoTime();
		final BigInteger decryptedShare = PaillierCipher.decrypt(privateKey, E);
		long e6 = System.nanoTime();
		System.out.println("Done. Took: " + ((e6 - s6) / 1_000_000.0) + " ms");
		System.out.println("Recovered plaintext: " + share.equals(decryptedShare));
		System.out.println("Result: " + decryptedShare);
		Assert.assertEquals(share, decryptedShare);
		System.out.println();

	}

}
