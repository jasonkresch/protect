/*
 * Copyright (c) IBM Corporation 2018. All Rights Reserved.
 * Project name: pross
 * This project is licensed under the MIT License, see LICENSE.
 */

package com.ibm.pross.server.messages.payloads.refresh;

import java.util.Arrays;

import com.ibm.pross.server.messages.Payload;

public class RefreshRebuttal implements Payload {

	private static final long serialVersionUID = -5936514281060059359L;

	private final long updateTime;
	private final int accuser;
	private final byte[] rebuttalEvidence;

	public RefreshRebuttal(final long updateTime, final int accuser, final byte[] rebuttalEvidence) {
		this.updateTime = updateTime;
		this.accuser = accuser;
		this.rebuttalEvidence = rebuttalEvidence;
	}

	@Override
	public OpCode getOpcode() {
		return OpCode.REFRESH_REBUTTAL;
	}

	public long getUpdateTime() {
		return updateTime;
	}

	public int getAccuser() {
		return accuser;
	}

	public byte[] getRebuttalEvidence() {
		return rebuttalEvidence;
	}

	@Override
	public String toString() {
		return "RefreshRebuttal [updateTime=" + updateTime + ", accuser=" + accuser + ", rebuttalEvidence=" + Arrays.toString(rebuttalEvidence) + "]";
	}

}
