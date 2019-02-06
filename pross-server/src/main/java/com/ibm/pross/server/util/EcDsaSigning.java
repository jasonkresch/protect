/*
 * Copyright (c) IBM Corporation 2018. All Rights Reserved.
 * Project name: pross
 * This project is licensed under the MIT License, see LICENSE.
 */

package com.ibm.pross.server.util;

import java.io.Serializable;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.util.concurrent.atomic.AtomicInteger;

import com.ibm.pross.server.messages.MessageSignature;
import com.ibm.pross.server.messages.PublicMessage;
import com.ibm.pross.server.messages.RelayedMessage;

import net.i2p.crypto.eddsa.EdDSASecurityProvider;

public class EcDsaSigning {

	// TODO: Look up how to do RSA-PSS, might need BouncyCastle
	// private final static String DEFAULT_ALGORITHM =
	// CommonConfiguration.SIGNATURE_ALGORITHM;
	private final static String DEFAULT_ALGORITHM = "NONEwithEdDSA";

	// TODO: Get to work
	// private static final String PROVIDER = "SunEC";
	// private static final String PROVIDER = "BC";
	private static final String PROVIDER = EdDSASecurityProvider.PROVIDER_NAME;

	// FIXME: Remove these
	public static final AtomicInteger signCount = new AtomicInteger(0);
	public static final AtomicInteger verCount = new AtomicInteger(0);

	public static byte[] toSerializedBytes(final Serializable message) {
		final byte[] messageBytes;
		if (message instanceof RelayedMessage) {
			messageBytes = MessageSerializer.serializeRelayedMessage((RelayedMessage) message);
		} else if (message instanceof PublicMessage) {
			messageBytes = MessageSerializer.serializeMessage((PublicMessage) message);
		} else {
			throw new IllegalArgumentException("Unknown message type");
		}
		return messageBytes;
	}

	public static boolean verifySignature(final Serializable message, final MessageSignature signature,
			final PublicKey senderPublicKey) {

		verCount.incrementAndGet();

		try {
			final Signature signingContext = Signature.getInstance(signature.getAlgorithm(), PROVIDER);
			signingContext.initVerify(senderPublicKey);
			try {
				final byte[] messageBytes = toSerializedBytes(message);
				signingContext.update(messageBytes);
				return signingContext.verify(signature.getSignatureBytes());
			} catch (SignatureException e) {
				// Signature check failed
				return false;
			}

		} catch (NoSuchAlgorithmException | InvalidKeyException | NoSuchProviderException e) {
			throw new IllegalArgumentException(e);
		}
	}

	public static MessageSignature createSignature(final Serializable message, final PrivateKey senderSigningKey) {

		// Generate signautres
		// final Digest digest = DigestFactory.createSHA512();
		// final HMacDSAKCalculator kCalculator = new HMacDSAKCalculator(digest);
		// final ECDSASigner signer = new ECDSASigner(kCalculator);
		// signer.init(forSigning, param);

		signCount.incrementAndGet();

		try {
			// Create signing context
			final Signature signingContext = Signature.getInstance(DEFAULT_ALGORITHM, PROVIDER);
			signingContext.initSign(senderSigningKey);

			// Serialize message to sign it
			final byte[] messageBytes = toSerializedBytes(message);
			signingContext.update(messageBytes);

			// Compute and return signature
			byte[] signatureBytes = signingContext.sign();
			return new MessageSignature(signatureBytes, DEFAULT_ALGORITHM);

		} catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException | NoSuchProviderException e) {
			throw new RuntimeException(e);
		}

	}
}
