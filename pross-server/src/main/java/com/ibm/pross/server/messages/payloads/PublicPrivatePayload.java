/*
 * Copyright (c) IBM Corporation 2018. All Rights Reserved.
 * Project name: pross
 * This project is licensed under the MIT License, see LICENSE.
 */

package com.ibm.pross.server.messages.payloads;

import com.ibm.pross.server.messages.Payload;

public class PublicPrivatePayload implements Payload {

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

}
