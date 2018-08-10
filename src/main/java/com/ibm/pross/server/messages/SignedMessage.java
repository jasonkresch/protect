/*
 * Copyright (c) IBM Corporation 2018. All Rights Reserved.
 * Project name: pross
 * This project is licensed under the MIT License, see LICENSE.
 */

package com.ibm.pross.server.messages;

import java.io.Serializable;
import java.security.PrivateKey;
import java.security.PublicKey;

import com.ibm.pross.common.util.crypto.EcDsaSigning;

/**
 * A signed message is a message object (either public or a private message)
 * with an accompanying signature
 */
public class SignedMessage implements Serializable {

	private static final long serialVersionUID = -1081969452777215305L;

	// Publicly broadcast message
	// m = (m' = (i, m), SIG_i(m'))

	// Privately sent message to a single recipient with index j
	// m = (m' = (i, j, ENC_j(m)), SIG_i(m'))

	private final Message message;
	private final MessageSignature signature;

	/**
	 * Constructor which takes a message and computes a message signature with
	 * the sender private key
	 * 
	 * @param message
	 * @param senderSigningKey
	 */
	public SignedMessage(final Message message, final PrivateKey senderSigningKey) {
		this(message, EcDsaSigning.createSignature(message, senderSigningKey));
	}

	/**
	 * Constructor which takes a message and a message signature
	 * 
	 * @param message
	 *            The message
	 * @param signature
	 *            The accompanying signature of the message sender
	 */
	public SignedMessage(final Message message, final MessageSignature signature) {
		this.message = message;
		this.signature = signature;
	}

	public Message getMessage() {
		return message;
	}

	public MessageSignature getSignature() {
		return signature;
	}

	/**
	 * Returns true if the signature is valid for the given message
	 * 
	 * @param senderPublicKey
	 *            The public key of the sender
	 * @return
	 */
	public boolean isSignatureValid(final PublicKey senderPublicKey) {
		return EcDsaSigning.verifySignature(this.message, this.signature, senderPublicKey);
	}

	@Override
	public String toString() {
		return "SignedMessage [message=" + message + ", signature=" + signature + "]";
	}

}
