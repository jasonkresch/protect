/*
 * Copyright (c) IBM Corporation 2018. All Rights Reserved.
 * Project name: pross
 * This project is licensed under the MIT License, see LICENSE.
 */

package com.ibm.pross.server.messages.payloads.optbft;

import com.ibm.pross.server.messages.Payload;
import com.ibm.pross.server.messages.SignedMessage;

public class CertificationPayload implements Payload {

	private static final long serialVersionUID = -1794607706408137757L;

	private final long messagePosition;
	private final SignedMessage bftMessage;

	public CertificationPayload(final long messagePosition, final SignedMessage bftMessage) {
		this.messagePosition = messagePosition;
		this.bftMessage = bftMessage;
	}

	@Override
	public OpCode getOpcode() {
		return OpCode.BFT_CERTIFICATION;
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


	
	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((bftMessage == null) ? 0 : bftMessage.hashCode());
		result = prime * result + (int) (messagePosition ^ (messagePosition >>> 32));
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
		CertificationPayload other = (CertificationPayload) obj;
		if (bftMessage == null) {
			if (other.bftMessage != null)
				return false;
		} else if (!bftMessage.equals(other.bftMessage))
			return false;
		if (messagePosition != other.messagePosition)
			return false;
		return true;
	}

}
