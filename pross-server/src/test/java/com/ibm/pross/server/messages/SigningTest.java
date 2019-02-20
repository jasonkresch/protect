/*
 * Copyright (c) IBM Corporation 2018. All Rights Reserved.
 * Project name: pross
 * This project is licensed under the MIT License, see LICENSE.
 */

package com.ibm.pross.server.messages;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.spec.ECGenParameterSpec;
import java.util.TreeSet;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;

import com.ibm.pross.common.CommonConfiguration;
import com.ibm.pross.server.messages.MessageSignature;
import com.ibm.pross.server.messages.PublicMessage;
import com.ibm.pross.server.messages.payloads.refresh.RefreshAccusations;
import com.ibm.pross.server.util.MessageSigningUtil;

public class SigningTest {

	@BeforeClass
	public static void setupBeforeClass()
	{
		Security.addProvider(new BouncyCastleProvider());
	}
	
	private KeyPair generateKeyPair() {

		// Initalize key pair generator
		final KeyPairGenerator keyGen;
		try {
			keyGen = KeyPairGenerator.getInstance("ECDSA", BouncyCastleProvider.PROVIDER_NAME);
			keyGen.initialize(new ECGenParameterSpec(CommonConfiguration.CURVE.getName()));
		} catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException | NoSuchProviderException e) {
			throw new RuntimeException(e);
		}

		// Create key pair
		return keyGen.generateKeyPair();
	}

	@Test
	public void testCreateVerifySignatureEcDsa() {

		final KeyPair keyPair = generateKeyPair();

		final PublicMessage message = new PublicMessage(0, new RefreshAccusations(1, new TreeSet<Integer>()));
		final MessageSignature signature = MessageSigningUtil.createSignature(message, keyPair.getPrivate());

		Assert.assertTrue(MessageSigningUtil.verifySignature(message, signature, keyPair.getPublic()));
	}

}
