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

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + accuser;
		result = prime * result + Arrays.hashCode(rebuttalEvidence);
		result = prime * result + (int) (updateTime ^ (updateTime >>> 32));
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
		RefreshRebuttal other = (RefreshRebuttal) obj;
		if (accuser != other.accuser)
			return false;
		if (!Arrays.equals(rebuttalEvidence, other.rebuttalEvidence))
			return false;
		if (updateTime != other.updateTime)
			return false;
		return true;
	}

	
}
