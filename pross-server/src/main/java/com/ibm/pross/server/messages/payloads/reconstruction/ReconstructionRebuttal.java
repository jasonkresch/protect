/*
 * Copyright (c) IBM Corporation 2018. All Rights Reserved.
 * Project name: pross
 * This project is licensed under the MIT License, see LICENSE.
 */

package com.ibm.pross.server.messages.payloads.reconstruction;

import java.util.Arrays;

import com.ibm.pross.server.messages.Payload;

public class ReconstructionRebuttal extends Payload {

	private static final long serialVersionUID = -6432823589747837543L;

	private final long updateTime;
	private final int corruptShareholder;
	private final int accuser;
	private final byte[] rebuttalEvidence;

	public ReconstructionRebuttal(final long updateTime, final int corruptShareholder, final int accuser,
			final byte[] rebuttalEvidence) {
		super(null, null);
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

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + accuser;
		result = prime * result + corruptShareholder;
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
		ReconstructionRebuttal other = (ReconstructionRebuttal) obj;
		if (accuser != other.accuser)
			return false;
		if (corruptShareholder != other.corruptShareholder)
			return false;
		if (!Arrays.equals(rebuttalEvidence, other.rebuttalEvidence))
			return false;
		if (updateTime != other.updateTime)
			return false;
		return true;
	}

	
	
}
