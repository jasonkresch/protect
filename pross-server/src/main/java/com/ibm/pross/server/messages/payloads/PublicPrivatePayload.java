/*
 * Copyright (c) IBM Corporation 2018. All Rights Reserved.
 * Project name: pross
 * This project is licensed under the MIT License, see LICENSE.
 */

package com.ibm.pross.server.messages.payloads;

import com.ibm.pross.server.messages.Payload;

public class PublicPrivatePayload extends Payload {

	private static final long serialVersionUID = 412885741324918495L;

	private final Payload publicPayload;
	private final Payload privatePayload;

	public PublicPrivatePayload(final Payload publicPayload, final Payload privatePayload) {
		this.publicPayload = publicPayload;
		this.privatePayload = privatePayload;
	}

	public Payload getPublicPayload() {
		return publicPayload;
	}

	public Payload getPrivatePayload() {
		return privatePayload;
	}

	@Override
	public OpCode getOpcode() {
		return publicPayload.getOpcode();
	}

	@Override
	public String toString() {
		return "PublicPrivatePayload [publicPayload=" + publicPayload + ", privatePayload=" + privatePayload + "]";
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((privatePayload == null) ? 0 : privatePayload.hashCode());
		result = prime * result + ((publicPayload == null) ? 0 : publicPayload.hashCode());
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
		PublicPrivatePayload other = (PublicPrivatePayload) obj;
		if (privatePayload == null) {
			if (other.privatePayload != null)
				return false;
		} else if (!privatePayload.equals(other.privatePayload))
			return false;
		if (publicPayload == null) {
			if (other.publicPayload != null)
				return false;
		} else if (!publicPayload.equals(other.publicPayload))
			return false;
		return true;
	}
	
	

}
