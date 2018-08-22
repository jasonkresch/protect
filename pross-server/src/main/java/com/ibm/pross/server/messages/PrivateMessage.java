/*
 * Copyright (c) IBM Corporation 2018. All Rights Reserved.
 * Project name: pross
 * This project is licensed under the MIT License, see LICENSE.
 */

package com.ibm.pross.server.messages;

import java.io.Serializable;
import java.security.PublicKey;

public class PrivateMessage implements Message, Serializable {

	private static final long serialVersionUID = 7376913964960269028L;

	// Always set to the index of the shareholder who created and sent this
	// message. Sender index is used to determine the public key by which to
	// verify the message authenticity
	private final int senderIndex;

	// Set to the recipient index, or the reserved index "0" if it is a publicly
	// broadcast message intended for everyone. If this is non-zero, the message
	// is encrypted with the public key of the recipient index, and its content
	// is therefore private.
	private final int recipientIndex;

	// The encrypted content of a private message. This must be decrypted with
	// the recipients private key to access the unencrypted content
	private final EncryptedPayload encryptedPayload;

	/**
	 * Constructs a private message readable only by a single recipient
	 * 
	 * @param senderIndex
	 *            The index of the sender (ourself)
	 * @param recipientIndex
	 *            The index of the intended recipient
	 * @param recipientEncryptionKey
	 *            The public key of the intended recipient, which will encrypt
	 *            the message content
	 * @param payload
	 *            The payload of the message
	 */
	public PrivateMessage(final int senderIndex, final int recipientIndex, final PublicKey recipientEncryptionKey,
			final Payload payload) {
		this.senderIndex = senderIndex;
		this.recipientIndex = recipientIndex;
		this.encryptedPayload = EciesEncryption.encrypt(payload, recipientEncryptionKey);
	}

	public int getRecipientIndex() {
		return recipientIndex;
	}

	public EncryptedPayload getEncryptedPayload() {
		return encryptedPayload;
	}
	
	@Override
	public int getSenderIndex() {
		return this.senderIndex;
	}

	@Override
	public boolean isRecipient(int index) {
		return (index == this.recipientIndex);
	}

}
