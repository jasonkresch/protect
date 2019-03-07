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

	public CertificationPayload(final long messagePosition, final SignedMessage bftMessage) {
		super(OpCode.BFT_CERTIFICATION, new SimpleEntry<Long, SignedMessage>(messagePosition, bftMessage));
	}

	@SuppressWarnings("unchecked")
	public long getMessagePosition() {
		return ((SimpleEntry<Long, SignedMessage>) super.getData()).getKey();
	}

	@SuppressWarnings("unchecked")
	public SignedMessage getBftMessage() {
		return ((SimpleEntry<Long, SignedMessage>) super.getData()).getValue();
	}

	@Override
	public String toString() {
		return "CertificationPayload [messagePosition=" + getMessagePosition() + ", bftMessage=" + getBftMessage()
				+ "]";
	}
}
