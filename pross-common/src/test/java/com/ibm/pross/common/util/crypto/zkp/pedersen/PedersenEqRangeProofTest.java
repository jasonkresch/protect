package com.ibm.pross.common.util.crypto.zkp.pedersen;

import static org.junit.Assert.fail;

import java.math.BigInteger;

import org.junit.Assert;
import org.junit.Test;

import com.ibm.pross.common.CommonConfiguration;
import com.ibm.pross.common.util.RandomNumberGenerator;
import com.ibm.pross.common.util.crypto.ecc.EcCurve;
import com.ibm.pross.common.util.crypto.ecc.EcPoint;
import com.ibm.pross.common.util.crypto.paillier.PaillierCipher;
import com.ibm.pross.common.util.crypto.paillier.PaillierKeyGenerator;
import com.ibm.pross.common.util.crypto.paillier.PaillierKeyPair;
import com.ibm.pross.common.util.crypto.paillier.PaillierPrivateKey;
import com.ibm.pross.common.util.crypto.paillier.PaillierPublicKey;
import com.ibm.pross.common.util.crypto.zkp.pedersen.PedersenEqRangeProof;
import com.ibm.pross.common.util.crypto.zkp.pedersen.PedersenEqRangeProofGenerator;
import com.ibm.pross.common.util.crypto.zkp.pedersen.PedersenEqRangeProofVerifier;

public class PedersenEqRangeProofTest {

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

		final BigInteger share1 = BigInteger.valueOf(12345);
		final BigInteger share2 = BigInteger.valueOf(54321);

		System.out.println("Encrypting share...");

		// Generate randomness: r
		final BigInteger n = publicKey.getN();

		// Warm up
		PaillierCipher.encrypt(publicKey, share1);
		PaillierCipher.encrypt(publicKey, share2);

		// Encrypt value
		long s2 = System.nanoTime();
		final BigInteger r1 = RandomNumberGenerator.generateRandomCoprimeInRange(n);
		final BigInteger Ea = PaillierCipher.encrypt(publicKey, share1, r1);
		long e2 = System.nanoTime();
		System.out.println("Done. Took: " + ((e2 - s2) / 1_000_000.0) + " ms");
		System.out.println();
		
		// Encrypt other value
		final BigInteger r2 = RandomNumberGenerator.generateRandomCoprimeInRange(n);
		final BigInteger Eb = PaillierCipher.encrypt(publicKey, share2, r2);

		// Create commitment
		System.out.println("Creating Pedersen commitment...");
		long s3 = System.nanoTime();
		final EcPoint S = curve.addPoints(curve.multiply(g, share1), curve.multiply(h, share2));
		long e3 = System.nanoTime();
		System.out.println("Done. Took: " + ((e3 - s3) / 1_000_000.0) + " ms");
		System.out.println();

		// Generating zero knowledge proof
		System.out.println("Generating zero knowledge proof...");
		long s4 = System.nanoTime();
		final PedersenEqRangeProof proof = PedersenEqRangeProofGenerator.generate(publicKey, share1, share2, r1, r2, Ea, Eb, S);
		long e4 = System.nanoTime();
		System.out.println("Done. Took: " + ((e4 - s4) / 1_000_000.0) + " ms");
		System.out.println();

		// Print proof
		System.out.println(proof);
		System.out.println("ZKP size: " + proof.getSize());
		System.out.println();

		// Validate proof
		System.out.println("Verifying zero knowledge proof...");
		long s5 = System.nanoTime();
		final boolean valid = PedersenEqRangeProofVerifier.isValid(proof, Ea, Eb, S, publicKey);
		long e5 = System.nanoTime();
		System.out.println("Done. Took: " + ((e5 - s5) / 1_000_000.0) + " ms");
		System.out.println("Proof is valid: " + valid);
		Assert.assertTrue(valid);
		System.out.println();

		// Validate decryption of first share
		System.out.println("Decrypting share...");
		long s6 = System.nanoTime();
		final BigInteger decryptedShare1 = PaillierCipher.decrypt(privateKey, Ea);
		long e6 = System.nanoTime();
		System.out.println("Done. Took: " + ((e6 - s6) / 1_000_000.0) + " ms");
		System.out.println("Recovered plaintext1: " + share1.equals(decryptedShare1));
		System.out.println("Result: " + decryptedShare1);
		Assert.assertEquals(share1, decryptedShare1);
		System.out.println();

		// Validate decryption of second share
		System.out.println("Decrypting share...");
		long s7 = System.nanoTime();
		final BigInteger decryptedShare2 = PaillierCipher.decrypt(privateKey, Eb);
		long e7 = System.nanoTime();
		System.out.println("Done. Took: " + ((e7 - s7) / 1_000_000.0) + " ms");
		System.out.println("Recovered plaintext2: " + share2.equals(decryptedShare2));
		System.out.println("Result: " + decryptedShare2);
		Assert.assertEquals(share2, decryptedShare2);
		System.out.println();
		
	}

}
