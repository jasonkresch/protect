/*
 * Copyright (c) IBM Corporation 2018. All Rights Reserved.
 * Project name: pross
 * This project is licensed under the MIT License, see LICENSE.
 */

package com.ibm.pross.common.util;

import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.util.concurrent.atomic.AtomicInteger;

import com.ibm.pross.common.CommonConfiguration;

public class SigningUtil {

	// FIXME: Remove these
	public static final AtomicInteger signCount = new AtomicInteger(0);
	public static final AtomicInteger verCount = new AtomicInteger(0);

	public static boolean verifyDefault(final byte[] message, final byte[] signature, final PublicKey senderPublicKey) {
		return verify(message, signature, senderPublicKey, getSigningAlgorithm(senderPublicKey));
	}

	public static boolean verify(final byte[] message, final byte[] signature, final PublicKey senderPublicKey,
			final String algorithm) {

		verCount.incrementAndGet();

		try {
			final Signature signingContext = Signature.getInstance(algorithm);
			signingContext.initVerify(senderPublicKey);
			try {
				signingContext.update(message);
				return signingContext.verify(signature);
			} catch (SignatureException e) {
				// Signature check failed
				return false;
			}

		} catch (NoSuchAlgorithmException | InvalidKeyException e) {
			throw new IllegalArgumentException(e);
		}

	}

	public static byte[] signDefault(final byte[] message, final PrivateKey signingKey) {
		return sign(message, signingKey, getSigningAlgorithm(signingKey));
	}

	public static byte[] sign(final byte[] message, final PrivateKey signingKey, final String algorithm) {

		signCount.incrementAndGet();

		try {
			// Create signing context
			final Signature signingContext = Signature.getInstance(algorithm);
			signingContext.initSign(signingKey);

			signingContext.update(message);

			// Compute and return signature
			byte[] signatureBytes = signingContext.sign();
			return signatureBytes;

		} catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
			throw new RuntimeException(e);
		}
	}

	/**
	 * Used to return the default signing algorithm for the given key type
	 * 
	 * @param key
	 * @return
	 */
	public static String getSigningAlgorithm(final Key key) {
		final String defaultAlgorithm;
		if (key.getAlgorithm().equals("ECDSA")) {
			defaultAlgorithm = CommonConfiguration.EC_SIGNATURE_ALGORITHM;
		} else if (key.getAlgorithm().equals("EdDSA")) {
			defaultAlgorithm = CommonConfiguration.ED_SIGNATURE_ALGORITHM;
		} else if (key.getAlgorithm().equals("RSA")) {
			defaultAlgorithm = CommonConfiguration.RSA_SIGNATURE_ALGORITHM;
		} else {
			throw new RuntimeException("Unknown key type: " + key.getAlgorithm());
		}
		return defaultAlgorithm;
	}
}
