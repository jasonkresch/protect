/*
 * Copyright (c) IBM Corporation 2018. All Rights Reserved.
 * Project name: pross
 * This project is licensed under the MIT License, see LICENSE.
 */

package com.ibm.pross.server.messages.payloads.reconstruction;

import java.util.Arrays;

import com.ibm.pross.server.messages.Payload;

public class ReconstructionRebuttal implements Payload {

	private static final long serialVersionUID = -6432823589747837543L;

	private final long updateTime;
	private final int corruptShareholder;
	private final int accuser;
	private final byte[] rebuttalEvidence;

	public ReconstructionRebuttal(final long updateTime, final int corruptShareholder, final int accuser,
			final byte[] rebuttalEvidence) {
		this.updateTime = updateTime;
		this.corruptShareholder = corruptShareholder;
		this.accuser = accuser;
		this.rebuttalEvidence = rebuttalEvidence;
	}

	@Override
	public OpCode getOpcode() {
		return OpCode.RECONSTRUCTION_REBUTTAL;
	}

	public long getUpdateTime() {
		return updateTime;
	}

	public int getCorruptShareholder() {
		return corruptShareholder;
	}

	public int getAccuser() {
		return accuser;
	}

	public byte[] getRebuttalEvidence() {
		return rebuttalEvidence;
	}

	@Override
	public String toString() {
		return "ReconstructionRebuttal [updateTime=" + updateTime + ", corruptShareholder=" + corruptShareholder
				+ ", accuser=" + accuser + ", rebuttalEvidence=" + Arrays.toString(rebuttalEvidence) + "]";
	}

}
