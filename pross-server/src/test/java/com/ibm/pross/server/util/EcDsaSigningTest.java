package com.ibm.pross.server.util;

import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.util.Random;

import javax.crypto.KeyGenerator;

import org.junit.Assert;
import org.junit.Test;

import com.ibm.pross.common.CommonConfiguration;
import com.ibm.pross.common.util.crypto.ecc.EcKeyGeneration;

import net.i2p.crypto.eddsa.EdDSASecurityProvider;

public class EcDsaSigningTest {

	static
	{
		Security.addProvider(new EdDSASecurityProvider());
	}
	
	@Test
	public void testSignaturePerformanceEcDsa() throws SignatureException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException {


		final String signatureAlgorithm = CommonConfiguration.EC_SIGNATURE_ALGORITHM;

		// Create message to sign
		final byte[] message = new byte[4096];
		final Random random = new Random();
		random.nextBytes(message);

		// Generate key pair
		final KeyPair keyPair = EcKeyGeneration.generateKeyPair();
		final PrivateKey privateKey = keyPair.getPrivate();

		final Signature signingContext = Signature.getInstance(signatureAlgorithm, "BC");
		signingContext.initSign(privateKey);
		
		// Warm up
		byte[] signature = null;
		for (int i = 0; i < 20; i++) {
			signingContext.update(message);
			signature = signingContext.sign();
		}
		System.out.println("Signature size: " + signature.length);

		// Do test
		long timeNs = 0;
		final int iterations = 1000;
		for (int i = 0; i < iterations; i++) {
			random.nextBytes(message);
			final long start = System.nanoTime();
			signingContext.update(message);
			signature = signingContext.sign();
			final long end = System.nanoTime();
			timeNs += (end - start);
		}

		System.out.println("Total time (ms): " + timeNs / (((long) iterations) * 1_000_000.0));
	}

	@Test
	public void testVerifyPerformanceEcDsa() throws SignatureException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException {

		final String signatureAlgorithm = CommonConfiguration.EC_SIGNATURE_ALGORITHM;

		// Create message to sign
		final byte[] message = new byte[4096];
		final Random random = new Random();
		random.nextBytes(message);

		// Generate key pair
		final KeyPair keyPair = EcKeyGeneration.generateKeyPair();
		final PublicKey publicKey = keyPair.getPublic();
		final PrivateKey privateKey = keyPair.getPrivate();

		final Signature signingContext = Signature.getInstance(signatureAlgorithm, "BC");
		signingContext.initSign(privateKey);
		
		// Verify
		final Signature verifyingContext = Signature.getInstance(signatureAlgorithm, "BC");
		verifyingContext.initVerify(publicKey);

		
		// Warm up
		byte[] signature = null;
		for (int i = 0; i < 20; i++) {
			signingContext.update(message);
			signature = signingContext.sign();
			verifyingContext.update(message);
			verifyingContext.verify(signature);
		}
		System.out.println("Signature size: " + signature.length);

		// Do test
		long timeNs = 0;
		final int iterations = 1000;
		for (int i = 0; i < iterations; i++) {
			random.nextBytes(message);
			signingContext.update(message);
			signature = signingContext.sign();
			final long start = System.nanoTime();
			verifyingContext.update(message);
			verifyingContext.verify(signature);
			final long end = System.nanoTime();
			timeNs += (end - start);
		}

		System.out.println("Total time (ms): " + timeNs / (((long) iterations) * 1_000_000.0));
	}

	@Test
	public void testECDSA()
			throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, SignatureException {

		final String signatureAlgorithm = CommonConfiguration.EC_SIGNATURE_ALGORITHM;

		// Create message to sign
		final byte[] message = new byte[4096];
		final Random random = new Random();
		random.nextBytes(message);

		// Generate key pair
		final KeyPair keyPair = EcKeyGeneration.generateKeyPair();
		final PublicKey publicKey = keyPair.getPublic();
		final PrivateKey privateKey = keyPair.getPrivate();

		// Sign
		final Signature signingContext = Signature.getInstance(signatureAlgorithm, "BC");
		signingContext.initSign(privateKey);
		signingContext.update(message);
		final byte[] signature = signingContext.sign();

		// Verify
		final Signature verifyingContext = Signature.getInstance(signatureAlgorithm, "BC");
		verifyingContext.initVerify(publicKey);
		verifyingContext.update(message);

		Assert.assertTrue(verifyingContext.verify(signature));
	}

	

	@Test
	public void testEd25519()
			throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, SignatureException {

		KeyPairGenerator keyGen = KeyPairGenerator.getInstance(EdDSASecurityProvider.PROVIDER_NAME);
		final KeyPair keyPair = keyGen.generateKeyPair();
		
		final String signatureAlgorithm = "NONEwithEdDSA";

		// Create message to sign
		final byte[] message = new byte[4096];
		final Random random = new Random();
		random.nextBytes(message);

		// Generate key pair
		final PublicKey publicKey = keyPair.getPublic();
		final PrivateKey privateKey = keyPair.getPrivate();

		// Sign
		final Signature signingContext = Signature.getInstance(signatureAlgorithm);
		signingContext.initSign(privateKey);
		signingContext.update(message);
		final byte[] signature = signingContext.sign();

		// Verify
		final Signature verifyingContext = Signature.getInstance(signatureAlgorithm);
		verifyingContext.initVerify(publicKey);
		verifyingContext.update(message);

		Assert.assertTrue(verifyingContext.verify(signature));
	}
	

	@Test
	public void testSignaturePerformanceEdDsa() throws SignatureException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException {

		final String signatureAlgorithm = "NONEwithEdDSA";

		// Create message to sign
		final byte[] message = new byte[4096];
		final Random random = new Random();
		random.nextBytes(message);

		// Generate key pair
		final KeyPairGenerator keyGen = KeyPairGenerator.getInstance(EdDSASecurityProvider.PROVIDER_NAME);
		final KeyPair keyPair = keyGen.generateKeyPair();
		final PrivateKey privateKey = keyPair.getPrivate();

		final Signature signingContext = Signature.getInstance(signatureAlgorithm);
		signingContext.initSign(privateKey);
		
		// Warm up
		byte[] signature = null;
		for (int i = 0; i < 20; i++) {
			signingContext.update(message);
			signature = signingContext.sign();
		}
		System.out.println("Signature size: " + signature.length);

		// Do test
		long timeNs = 0;
		final int iterations = 1000;
		for (int i = 0; i < iterations; i++) {
			random.nextBytes(message);
			final long start = System.nanoTime();
			signingContext.update(message);
			signature = signingContext.sign();
			final long end = System.nanoTime();
			timeNs += (end - start);
		}

		System.out.println("Total time (ms): " + timeNs / (((long) iterations) * 1_000_000.0));
	}

	@Test
	public void testVerifyPerformanceEdDsa() throws SignatureException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException {

		final String signatureAlgorithm = "NONEwithEdDSA";

		// Create message to sign
		final byte[] message = new byte[4096];
		final Random random = new Random();
		random.nextBytes(message);

		// Generate key pair
		final KeyPairGenerator keyGen = KeyPairGenerator.getInstance(EdDSASecurityProvider.PROVIDER_NAME);
		final KeyPair keyPair = keyGen.generateKeyPair();
		final PublicKey publicKey = keyPair.getPublic();
		final PrivateKey privateKey = keyPair.getPrivate();

		final Signature signingContext = Signature.getInstance(signatureAlgorithm);
		signingContext.initSign(privateKey);
		
		// Verify
		final Signature verifyingContext = Signature.getInstance(signatureAlgorithm);
		verifyingContext.initVerify(publicKey);

		
		// Warm up
		byte[] signature = null;
		for (int i = 0; i < 20; i++) {
			signingContext.update(message);
			signature = signingContext.sign();
			verifyingContext.update(message);
			verifyingContext.verify(signature);
		}
		System.out.println("Signature size: " + signature.length);

		// Do test
		long timeNs = 0;
		final int iterations = 1000;
		for (int i = 0; i < iterations; i++) {
			random.nextBytes(message);
			signingContext.update(message);
			signature = signingContext.sign();
			final long start = System.nanoTime();
			verifyingContext.update(message);
			verifyingContext.verify(signature);
			final long end = System.nanoTime();
			timeNs += (end - start);
		}

		System.out.println("Total time (ms): " + timeNs / (((long) iterations) * 1_000_000.0));
	}

}
