/*
 * Copyright (c) IBM Corporation 2018. All Rights Reserved.
 * Project name: pross
 * This project is licensed under the MIT License, see LICENSE.
 */

package com.ibm.pross.server.messages.payloads.optbft;

import java.util.AbstractMap.SimpleEntry;

import com.ibm.pross.server.messages.Payload;
import com.ibm.pross.server.messages.SignedMessage;

public class CertificationPayload extends Payload {

	private static final long serialVersionUID = -1794607706408137757L;

	private final long messagePosition;
	private final SignedMessage bftMessage;

	public CertificationPayload(final long messagePosition, final SignedMessage bftMessage) {
		super(OpCode.BFT_CERTIFICATION, new SimpleEntry<Long, SignedMessage>(messagePosition, bftMessage));
		this.messagePosition = messagePosition;
		this.bftMessage = bftMessage;
	}

	public long getMessagePosition() {
		return messagePosition;
	}

	public SignedMessage getBftMessage() {
		return bftMessage;
	}

	@Override
	public String toString() {
		return "CertificationPayload [messagePosition=" + messagePosition + ", bftMessage=" + bftMessage + "]";
	}
}
