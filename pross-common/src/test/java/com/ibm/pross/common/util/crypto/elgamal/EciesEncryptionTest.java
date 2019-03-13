package com.ibm.pross.common.util.crypto.elgamal;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.spec.ECGenParameterSpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;

/*
 * Copyright (c) IBM Corporation 2018. All Rights Reserved.
 * Project name: pross
 * This project is licensed under the MIT License, see LICENSE.
 */
public class EciesEncryptionTest {

	@BeforeClass
	public static void setupBeforeClass() {
		Security.addProvider(new BouncyCastleProvider());
	}

	@Test
	public void testEncryptDecrypt() throws Exception {

		final String name = "secp256r1";

		// NOTE just "EC" also seems to work here
		final KeyPairGenerator kpg = KeyPairGenerator.getInstance("ECDH", BouncyCastleProvider.PROVIDER_NAME);
		kpg.initialize(new ECGenParameterSpec(name));

		// Key pair to store public and private key
		final KeyPair keyPair = kpg.generateKeyPair();

		// Message to encrypt
		byte[] message = "hello".getBytes(StandardCharsets.UTF_8);

		// Encrypt
		final BigInteger r = EciesEncryption.generateR();
		byte[] encrypted = EciesEncryption.encrypt(message, r, keyPair.getPublic());

		// Decrypt
		byte[] decrypted = EciesEncryption.decrypt(encrypted, keyPair.getPrivate());
		System.out.println("Decrypted message: " + new String(decrypted));

		Assert.assertArrayEquals(message, decrypted);

	}

}
