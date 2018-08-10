/*
 * Copyright (c) IBM Corporation 2018. All Rights Reserved.
 * Project name: pross
 * This project is licensed under the MIT License, see LICENSE.
 */

package com.ibm.pross.server.messages;

import java.io.Serializable;

public class PublicMessage implements Message, Serializable {

	private static final long serialVersionUID = -8470206987302692599L;

	// Always set to the index of the shareholder who created and sent this
	// message. Sender index is used to determine the public key by which to
	// verify the message authenticity
	private final int senderIndex;

	// The content of the message
	private final Payload payload;

	/**
	 * Constructs a publicly readable broadcast message
	 * 
	 * @param senderIndex
	 *            The index of the sender (ourself)
	 * @param content
	 *            The content of the message to send
	 */
	public PublicMessage(final int senderIndex, final Payload payload) {
		this.senderIndex = senderIndex;
		this.payload = payload;
	}
	
	public Payload getPayload()
	{
		return payload;
	}

	@Override
	public int getSenderIndex() {
		return this.senderIndex;
	}

	@Override
	public boolean isRecipient(int index) {
		// This is a broadcast message, all shareholders are recipients
		return true;
	}

}
