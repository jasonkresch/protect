/*
 * Copyright (c) IBM Corporation 2018. All Rights Reserved.
 * Project name: pross
 * This project is licensed under the MIT License, see LICENSE.
 */

package com.ibm.pross.server.messages.payloads.dkg;

import java.util.Arrays;

import com.ibm.pross.common.util.crypto.ecc.EcPoint;
import com.ibm.pross.server.messages.Payload;

public class GenerationVssPublicPayload extends Payload {

	private static final long serialVersionUID = -3640250537454783435L;
	
	private final EcPoint[] feldmanValues;

	public GenerationVssPublicPayload(final EcPoint[] feldmanValues) {
		this.feldmanValues = feldmanValues;
	}

	@Override
	public OpCode getOpcode() {
		return OpCode.DKG_VSS;
	}


	public EcPoint[] getFeldmanValues() {
		return feldmanValues;
	}

	@Override
	public String toString() {
		return "GenerationVssPublicPayload [feldmanValues=" + Arrays.toString(feldmanValues) + "]";
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + Arrays.hashCode(feldmanValues);
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
		GenerationVssPublicPayload other = (GenerationVssPublicPayload) obj;
		if (!Arrays.equals(feldmanValues, other.feldmanValues))
			return false;
		return true;
	}

	
	
}
