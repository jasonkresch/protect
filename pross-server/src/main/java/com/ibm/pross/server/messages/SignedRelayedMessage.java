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
 * A signed relayed message is a relayed message object  with an accompanying signature
 */
public class SignedRelayedMessage implements Serializable {

	private static final long serialVersionUID = -6016991360657379064L;
	
	// Publicly broadcast message
	// m = (m' = (i, m), SIG_i(m'))

	// Privately sent message to a single recipient with index j
	// m = (m' = (i, j, ENC_j(m)), SIG_i(m'))

	private final RelayedMessage relayedMessage;
	private final MessageSignature signature;

	/**
	 * Constructor which takes a message and computes a message signature with
	 * the sender private key
	 * 
	 * @param message
	 * @param senderSigningKey
	 */
	public SignedRelayedMessage(final RelayedMessage relayedMessage, final PrivateKey senderSigningKey) {
		this(relayedMessage, MessageSigningUtil.createSignature(relayedMessage, senderSigningKey));
	}

	/**
	 * Constructor which takes a message and a message signature
	 * 
	 * @param message
	 *            The message
	 * @param signature
	 *            The accompanying signature of the message sender
	 */
	public SignedRelayedMessage(final RelayedMessage relayedMessage, final MessageSignature signature) {
		this.relayedMessage = relayedMessage;
		this.signature = signature;
	}

	public RelayedMessage getRelayedMessage() {
		return relayedMessage;
	}

	public MessageSignature getSignature() {
		return signature;
	}

	/**
	 * Returns true if the signature is valid for the given relayed message
	 * 
	 * @param senderPublicKey
	 *            The public key of the sender
	 * @return
	 */
	public boolean isSignatureValid(final PublicKey senderPublicKey) {
		return MessageSigningUtil.verifySignature(this.relayedMessage, this.signature, senderPublicKey);
	}

	@Override
	public String toString() {
		return "SignedRelayedMessage [relayedMessage=" + relayedMessage + ", signature=" + signature + "]";
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((relayedMessage == null) ? 0 : relayedMessage.hashCode());
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
		SignedRelayedMessage other = (SignedRelayedMessage) obj;
		if (relayedMessage == null) {
			if (other.relayedMessage != null)
				return false;
		} else if (!relayedMessage.equals(other.relayedMessage))
			return false;
		if (signature == null) {
			if (other.signature != null)
				return false;
		} else if (!signature.equals(other.signature))
			return false;
		return true;
	}

	
	
}
