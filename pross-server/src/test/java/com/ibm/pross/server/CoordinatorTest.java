/*
 * Copyright (c) IBM Corporation 2018. All Rights Reserved.
 * Project name: pross
 * This project is licensed under the MIT License, see LICENSE.
 */

package com.ibm.pross.server;

import static org.junit.Assert.fail;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.Security;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;

import com.ibm.pross.client.PrfClient;
import com.ibm.pross.common.CommonConfiguration;
import com.ibm.pross.common.util.crypto.ecc.EcPoint;
import com.ibm.pross.common.util.crypto.kdf.HmacKeyDerivationFunction;

public class CoordinatorTest {
/**
	public static Administration DEFAULT_ADMINISTRATION;
	
	@BeforeClass
	public static void setupBeforeClass() throws NoSuchAlgorithmException, BadPaddingException, IllegalBlockSizeException, ClassNotFoundException, IOException
	{
		Security.addProvider(new BouncyCastleProvider());
		CommonConfiguration.CURVE.getPointHasher().hashToCurve(new byte[1]);
		DEFAULT_ADMINISTRATION = createDefaultAdministration();
	}
	
	private static Administration createDefaultAdministration() throws BadPaddingException, IllegalBlockSizeException, ClassNotFoundException, IOException
	{
		// Create threshold parameters
		final int n = 5;
		final int updateThreshold = 4;
		final int threshold = 3;

		final Administration administration = new Administration(n, threshold, updateThreshold, false);
		
		return administration;
	}
	
	
	@Test
	public void testVerifyAllShares() {
		fail("Not yet implemented");
	}

	@Test
	public void testVerify() {
		fail("Not yet implemented");
	}

	@Test
	public void testRebuildAll() {
		fail("Not yet implemented");
	}

	@Test
	public void testRebuild() {
		fail("Not yet implemented");
	}

	@Test
	public void testUpdateAllKeyPairs() {
		fail("Not yet implemented");
	}

	@Test
	public void testUpdateKeyPair() {
		fail("Not yet implemented");
	}

	@Test
	public void testProcessUpdatePhase() {
		fail("Not yet implemented");
	}


	
	@Test
	public void testPrfClient() throws Exception {

		// Create shareholders and client
		final PrfClient prfClient = DEFAULT_ADMINISTRATION.provisionClient();

		// Derive a key
		System.out.println("Deriving KDF from bytes");
		final byte[] input = "test".getBytes(StandardCharsets.UTF_8);
		final HmacKeyDerivationFunction hkdf = prfClient.deriveKeyGeneratorFromBytes(input);
		Assert.assertNotNull(hkdf);
		
		// Wrap a key
		System.out.println("Wrapping a key");
		final EcPoint output1 = prfClient.derivePointFromBytes(input);
		System.out.println("Prf Output 1: " + output1);
		
		// Unwrap a key
		final EcPoint output2 = prfClient.derivePointFromBytes(input);
		System.out.println("Prf Output 2: " + output2);
		Assert.assertEquals(output1, output2);
	}
*/
}
