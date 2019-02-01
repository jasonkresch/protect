package com.ibm.pross.common.util.crypto.paillier;

import static org.junit.Assert.fail;

import java.math.BigInteger;

import org.junit.Test;

import com.ibm.pross.common.util.RandomNumberGenerator;

public class PaillierCipherTest {

	@Test
	public void testEncryptPaillierPublicKeyBigInteger() {
		fail("Not yet implemented");
	}

	@Test
	public void testEncryptPaillierPublicKeyBigIntegerBigInteger() {
		fail("Not yet implemented");
	}

	@Test
	public void testDecrypt() {
		fail("Not yet implemented");
	}
	
	@Test
	public void testEncryptPerformance() {
		
		final PaillierKeyGenerator keyGenerator = new PaillierKeyGenerator(2048);
		final PaillierKeyPair keyPair = keyGenerator.generate();
		
		// Generate random input
		final BigInteger n = keyPair.getPublicKey().getN();
		
		
		// Warm up
		BigInteger encrypted = null;
		for (int i = 0; i < 20; i++)
		{
			final BigInteger x = RandomNumberGenerator.generateRandomInteger(n);
			encrypted = PaillierCipher.encrypt(keyPair.getPublicKey(), x);
		}
		System.out.println("size: " + (encrypted.toByteArray().length));
		
		// Do test
		long timeNs = 0;
		final int iterations = 1000;
		final PaillierPublicKey publicKey = keyPair.getPublicKey();
		for (int i = 0; i < iterations; i++)
		{
			final BigInteger x = RandomNumberGenerator.generateRandomInteger(n);
			final long start = System.nanoTime();
			PaillierCipher.encrypt(publicKey, x);
			final long end = System.nanoTime();
			timeNs += (end - start);
		}
		
		System.out.println("Total time (ms): " + timeNs / (((long)iterations) * 1_000_000.0));
	}
	

	@Test
	public void testDecryptPerformance() {
		
		final PaillierKeyGenerator keyGenerator = new PaillierKeyGenerator(2048);
		final PaillierKeyPair keyPair = keyGenerator.generate();
		
		// Generate random input
		final BigInteger n = keyPair.getPublicKey().getN();
		
		
		// Warm up
		for (int i = 0; i < 20; i++)
		{
			final BigInteger x = RandomNumberGenerator.generateRandomInteger(n);
			PaillierCipher.encrypt(keyPair.getPublicKey(), x);
		}
		
		// Do test
		long timeNs = 0;
		final int iterations = 1000;
		final PaillierPublicKey publicKey = keyPair.getPublicKey();
		final PaillierPrivateKey privateKey = keyPair.getPrivateKey();
		for (int i = 0; i < iterations; i++)
		{
			final BigInteger x = RandomNumberGenerator.generateRandomInteger(n);
			final BigInteger c = PaillierCipher.encrypt(publicKey, x);
			final long start = System.nanoTime();
			PaillierCipher.decrypt(privateKey, c);
			final long end = System.nanoTime();
			timeNs += (end - start);
		}
		
		System.out.println("Total time (ms): " + timeNs / (((long)iterations) * 1_000_000.0));
	}


}
