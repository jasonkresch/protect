/*
 * Copyright (c) IBM Corporation 2018. All Rights Reserved.
 * Project name: pross
 * This project is licensed under the MIT License, see LICENSE.
 */

package com.ibm.pross.server.messages;

import java.io.Serializable;
import java.util.NavigableMap;

public class SemiPrivateMessage implements Message, Serializable {

	private static final long serialVersionUID = 7376913964960269028L;

	// Always set to the index of the shareholder who created and sent this
	// message. Sender index is used to determine the public key by which to
	// verify the message authenticity
	private final int senderIndex;

	// The public content of this message
	private final Payload publicPayload;

	// The one or more encrypted payloads of a private message. This must be
	// decrypted with the recipients private key to access the unencrypted
	// content
	// This must be sorted to have a deterministic serialization (for signature
	// validation)
	private final NavigableMap<Integer, EncryptedPayload> encryptedPayloads;

	/**
	 * Constructs a message with a public and a private component
	 * 
	 * @param senderIndex
	 *            The index of the sender (ourself)
	 * @param publicPayload
	 *            The payload of the message visible to everypone
	 * @param encryptedPayloads
	 *            A map of recipient indices to their own private part of this
	 *            message
	 */
	public SemiPrivateMessage(final int senderIndex, final Payload publicPayload,
			final NavigableMap<Integer, EncryptedPayload> encryptedPayloads) {
		this.senderIndex = senderIndex;
		this.publicPayload = publicPayload;
		this.encryptedPayloads = encryptedPayloads;
	}

	public Payload getPublicPayload() {
		return this.publicPayload;
	}

	public EncryptedPayload getEncryptedPayload(int recipientIndex) {
		return this.encryptedPayloads.get(recipientIndex);
	}

	@Override
	public int getSenderIndex() {
		return this.senderIndex;
	}

	@Override
	public boolean isRecipient(int index) {
		return this.encryptedPayloads.containsKey(index);
	}

}
