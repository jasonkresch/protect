/*
 * Copyright (c) IBM Corporation 2018. All Rights Reserved.
 * Project name: pross
 * This project is licensed under the MIT License, see LICENSE.
 */

package com.ibm.pross.server.messages;

import java.io.Serializable;
import java.security.PrivateKey;
import java.security.PublicKey;

import com.ibm.pross.server.util.MessageSigningUtil;

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

	private final PublicMessage message;
	private final MessageSignature signature;

	/**
	 * Constructor which takes a message and computes a message signature with
	 * the sender private key
	 * 
	 * @param message
	 * @param senderSigningKey
	 */
	public SignedMessage(final PublicMessage message, final PrivateKey senderSigningKey) {
		this(message, MessageSigningUtil.createSignature(message, senderSigningKey));
	}

	/**
	 * Constructor which takes a message and a message signature
	 * 
	 * @param message
	 *            The message
	 * @param signature
	 *            The accompanying signature of the message sender
	 */
	public SignedMessage(final PublicMessage message, final MessageSignature signature) {
		this.message = message;
		this.signature = signature;
	}

	public PublicMessage getMessage() {
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
		return MessageSigningUtil.verifySignature((PublicMessage) this.message, this.signature, senderPublicKey);
	}

	@Override
	public String toString() {
		return "SignedMessage [message=" + message + ", signature=" + signature + "]";
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((message == null) ? 0 : message.hashCode());
		result = prime * result + ((signature == null) ? 0 : signature.hashCode());
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		SignedMessage other = (SignedMessage) obj;
		if (message == null) {
			if (other.message != null)
				return false;
		} else if (!message.equals(other.message))
			return false;
		if (signature == null) {
			if (other.signature != null)
				return false;
		} else if (!signature.equals(other.signature))
			return false;
		return true;
	}

	
}
