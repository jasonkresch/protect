/*
 * Copyright (c) IBM Corporation 2018. All Rights Reserved.
 * Project name: pross
 * This project is licensed under the MIT License, see LICENSE.
 */

package com.ibm.pross.common.util.crypto;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.ECGenParameterSpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import com.ibm.pross.common.CommonConfiguration;
import com.ibm.pross.common.util.crypto.ecc.EcCurve;
import com.ibm.pross.common.util.crypto.ecc.EcPoint;

public class EcKeyGeneration {

	// Static fields
	final public static EcCurve curve = CommonConfiguration.CURVE;
	final public static BigInteger r = curve.getR();
	final public static EcPoint G = curve.getG();

	/**
	 * Generate elliptic curve key pairs
	 * 
	 * @return
	 */
	public static final KeyPair generateKeyPair() {

		// Initalize key pair generator
		final KeyPairGenerator keyGen;
		try {
			keyGen = KeyPairGenerator.getInstance("ECDSA", BouncyCastleProvider.PROVIDER_NAME);
			keyGen.initialize(new ECGenParameterSpec(curve.getName()));
			return keyGen.generateKeyPair();
		} catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException | NoSuchProviderException e) {
			throw new RuntimeException(e);
		}

	}

}
