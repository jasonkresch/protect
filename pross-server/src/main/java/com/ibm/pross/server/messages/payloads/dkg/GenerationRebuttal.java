/*
 * Copyright (c) IBM Corporation 2018. All Rights Reserved.
 * Project name: pross
 * This project is licensed under the MIT License, see LICENSE.
 */

package com.ibm.pross.server.messages.payloads.dkg;

import java.util.Arrays;

import com.ibm.pross.server.messages.Payload;

public class GenerationRebuttal implements Payload {

	private static final long serialVersionUID = 4639871774606044115L;
	
	private final int accuser;
	private final byte[] rebuttalEvidence;

	public GenerationRebuttal(final int accuser, final byte[] rebuttalEvidence) {
		this.accuser = accuser;
		this.rebuttalEvidence = rebuttalEvidence;
	}

	@Override
	public OpCode getOpcode() {
		return OpCode.DKG_REBUTTAL;
	}

	public int getAccuser() {
		return accuser;
	}

	public byte[] getRebuttalEvidence() {
		return rebuttalEvidence;
	}

	@Override
	public String toString() {
		return "GenerationRebuttal [accuser=" + accuser + ", rebuttalEvidence=" + Arrays.toString(rebuttalEvidence) + "]";
	}

}
