/*
 * Copyright (c) IBM Corporation 2018. All Rights Reserved.
 * Project name: pross
 * This project is licensed under the MIT License, see LICENSE.
 */

package com.ibm.pross.server.util;

import java.io.Serializable;
import java.security.PrivateKey;
import java.security.PublicKey;

import com.ibm.pross.common.util.SigningUtil;
import com.ibm.pross.server.messages.MessageSignature;
import com.ibm.pross.server.messages.Message;
import com.ibm.pross.server.messages.RelayedMessage;

public class MessageSigningUtil {

	public static byte[] toSerializedBytes(final Serializable message) {
		final byte[] messageBytes;
		if (message instanceof RelayedMessage) {
			messageBytes = MessageSerializer.serializeRelayedMessage((RelayedMessage) message);
		} else if (message instanceof Message) {
			messageBytes = MessageSerializer.serializeMessage((Message) message);
		} else {
			throw new IllegalArgumentException("Unknown message type");
		}
		return messageBytes;
	}

	public static boolean verifySignature(final Serializable message, final MessageSignature signature,
			final PublicKey senderPublicKey) {
		final byte[] messageBytes = toSerializedBytes(message);
		return SigningUtil.verify(messageBytes, signature.getSignatureBytes(), senderPublicKey, signature.getAlgorithm());
	}


	public static MessageSignature createSignature(final Serializable message, final PrivateKey senderSigningKey) {
		// Determine algorithm to sign with
		final String defaultAlgorithm = SigningUtil.getSigningAlgorithm(senderSigningKey);

		// Serialize message
		final byte[] messageBytes = toSerializedBytes(message);
		final byte[] signatureBytes = SigningUtil.sign(messageBytes, senderSigningKey, defaultAlgorithm);

		// Return a Message signature containing the signature and algorithm
		return new MessageSignature(signatureBytes, defaultAlgorithm);
	}

}
