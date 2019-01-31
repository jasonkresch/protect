/*
 * Copyright (c) IBM Corporation 2018. All Rights Reserved.
 * Project name: pross
 * This project is licensed under the MIT License, see LICENSE.
 */

package com.ibm.pross.server.messages;

import java.io.Serializable;
import java.util.NavigableMap;
import java.util.UUID;

public class SemiPrivateMessage implements Message, Serializable {

	private static final long serialVersionUID = 7376913964960269028L;

	// This is a hack to deal with hashcode and equality not working for sets
	private final UUID messageId = UUID.randomUUID();
	
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

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((messageId == null) ? 0 : messageId.hashCode());
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
		SemiPrivateMessage other = (SemiPrivateMessage) obj;
		if (messageId == null) {
			if (other.messageId != null)
				return false;
		} else if (!messageId.equals(other.messageId))
			return false;
		return true;
	}


	
}
