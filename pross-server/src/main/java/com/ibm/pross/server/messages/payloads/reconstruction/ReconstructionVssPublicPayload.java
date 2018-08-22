/*
 * Copyright (c) IBM Corporation 2018. All Rights Reserved.
 * Project name: pross
 * This project is licensed under the MIT License, see LICENSE.
 */

package com.ibm.pross.server.messages.payloads.reconstruction;

import java.util.Arrays;

import com.ibm.pross.common.util.crypto.ecc.EcPoint;
import com.ibm.pross.server.messages.Payload;

public class ReconstructionVssPublicPayload implements Payload {

	private static final long serialVersionUID = 159815865690590859L;

	private final long updateTime;
	private final int corruptShareholder;
	private final EcPoint[] feldmanValues;

	public ReconstructionVssPublicPayload(final long updateTime,final int corruptShareholder, final EcPoint[] feldmanValues) {
		this.updateTime = updateTime;
		this.corruptShareholder = corruptShareholder;
		this.feldmanValues = feldmanValues;
	}

	@Override
	public OpCode getOpcode() {
		return OpCode.RECONSTRUCTION_VSS;
	}

	public long getUpdateTime() {
		return updateTime;
	}

	public int getCorruptShareholder() {
		return corruptShareholder;
	}

	public EcPoint[] getFeldmanValues() {
		return feldmanValues;
	}

	@Override
	public String toString() {
		return "VssPublicReconstructionPayload [updateTime=" + updateTime + ", corruptShareholder=" + corruptShareholder
				+ ", feldmanValues=" + Arrays.toString(feldmanValues) + "]";
	}

}
