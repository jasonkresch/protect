/*
 * Copyright (c) IBM Corporation 2018. All Rights Reserved.
 * Project name: pross
 * This project is licensed under the MIT License, see LICENSE.
 */

package com.ibm.pross.server.messages.payloads.dkg;

import java.util.Arrays;

import com.ibm.pross.server.messages.Payload;

public class GenerationRebuttal extends Payload {

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

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + accuser;
		result = prime * result + Arrays.hashCode(rebuttalEvidence);
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
		GenerationRebuttal other = (GenerationRebuttal) obj;
		if (accuser != other.accuser)
			return false;
		if (!Arrays.equals(rebuttalEvidence, other.rebuttalEvidence))
			return false;
		return true;
	}
	
	

}
