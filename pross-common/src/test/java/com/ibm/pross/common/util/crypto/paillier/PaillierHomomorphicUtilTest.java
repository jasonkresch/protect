package com.ibm.pross.common.util.crypto.paillier;

import static org.junit.Assert.fail;

import java.math.BigInteger;

import org.junit.Assert;
import org.junit.Test;


public class PaillierHomomorphicUtilTest {

	@Test
	public void testAddCiphertexts() {
		fail("Not yet implemented");
	}

	@Test
	public void testSubtractCiphertexts() {
		fail("Not yet implemented");
	}

	@Test
	public void testAddConstant() {
		fail("Not yet implemented");
	}

	@Test
	public void testSubtractConstant() {
		fail("Not yet implemented");
	}

	@Test
	public void testMultiplyConstant() {
		fail("Not yet implemented");
	}

	@Test
	public void testDivideConstant() {
		fail("Not yet implemented");
	}

	@Test
	public void testAll() {

		// Generate encryption key
		System.out.println("Generating key...");
		final PaillierKeyGenerator keyGenerator = new PaillierKeyGenerator(1024);
		final PaillierKeyPair keyPair = keyGenerator.generate();
		System.out.println("Done.");

		// Get public and private keys
		final PaillierPublicKey publicKey = keyPair.getPublicKey();
		final PaillierPrivateKey privateKey = keyPair.getPrivateKey();

		// Do encryption
		final BigInteger message = BigInteger.valueOf(15);
		final BigInteger encrypted = PaillierCipher.encrypt(publicKey, message);

		// Do decryption
		final BigInteger decrypted = PaillierCipher.decrypt(privateKey, encrypted);
		Assert.assertEquals(15, decrypted.intValue());

		// Check
		System.out.println(message);
		System.out.println(encrypted);
		System.out.println(decrypted);

		// Encrypt second plaintext
		final BigInteger message2 = BigInteger.valueOf(2);
		long start = System.nanoTime();
		final BigInteger encrypted2 = PaillierCipher.encrypt(publicKey, message2);
		long end = System.nanoTime();
		Assert.assertNotEquals(2, encrypted2.intValue());
		System.out.println(encrypted2);
		System.out.println("Encryption took: " + ((long) (end - start) / 1_000_000.0) + " ms");

		// Addition of ciphertexts
		final BigInteger encryptedSum = PaillierHomomorphicUtil.addCiphertexts(publicKey, encrypted, encrypted2);
		final long start2 = System.nanoTime();
		final BigInteger decryptedSum = PaillierCipher.decrypt(privateKey, encryptedSum);
		final long end2 = System.nanoTime();
		System.out.println("Decryption took: " + ((long) (end2 - start2) / 1_000_000.0) + " ms");
		System.out.println(decryptedSum);
		Assert.assertEquals(17, decryptedSum.intValue());

		// Multiply by constant
		final BigInteger factor = BigInteger.valueOf(3);
		final BigInteger encryptedProd = PaillierHomomorphicUtil.multiplyConstant(publicKey, encryptedSum, factor);
		final BigInteger decryptedProduct = PaillierCipher.decrypt(privateKey, encryptedProd);
		System.out.println(decryptedProduct);
		Assert.assertEquals(51, decryptedProduct.intValue());

		// Divide by constant
		final BigInteger divisor = BigInteger.valueOf(17);
		final BigInteger encryptedDivided = PaillierHomomorphicUtil.divideConstant(publicKey, encryptedProd, divisor);
		final BigInteger result = PaillierCipher.decrypt(privateKey, encryptedDivided);
		System.out.println(result);
		Assert.assertEquals(3, result.intValue());

		// Add constant
		final BigInteger sumConstantEnc = PaillierHomomorphicUtil.addConstant(publicKey, encryptedDivided,
				BigInteger.valueOf(20));
		final BigInteger sumConstant = PaillierCipher.decrypt(privateKey, sumConstantEnc);
		System.out.println(sumConstant);
		Assert.assertEquals(23, sumConstant.intValue());

		// Subtract constant
		final BigInteger subConstantEnc = PaillierHomomorphicUtil.subtractConstant(publicKey, sumConstantEnc,
				BigInteger.valueOf(5));
		final BigInteger subConstant = PaillierCipher.decrypt(privateKey, subConstantEnc);
		System.out.println(subConstant);
		Assert.assertEquals(18, subConstant.intValue());

	}

}
