/*
 * Copyright (c) IBM Corporation 2018. All Rights Reserved.
 * Project name: pross
 * This project is licensed under the MIT License, see LICENSE.
 */

package com.ibm.pross.server.messages.payloads.reconstruction;

import java.util.Arrays;

import com.ibm.pross.common.util.crypto.ecc.EcPoint;
import com.ibm.pross.server.messages.Payload;

public class ReconstructionDetectCorrupt implements Payload {

	private static final long serialVersionUID = -2536029408832984608L;

	private final long updateTime;
	private final EcPoint[] sharePublicKeys;

	public ReconstructionDetectCorrupt(final long updateTime, final EcPoint[] sharePublicKeys) {
		this.updateTime = updateTime;
		this.sharePublicKeys = sharePublicKeys;
	}

	@Override
	public OpCode getOpcode() {
		return OpCode.RECONSTRUCTION_DETECT_CORRUPT;
	}

	public long getUpdateTime() {
		return updateTime;
	}

	public EcPoint[] getSharePublicKeys() {
		return this.sharePublicKeys;
	}

	@Override
	public String toString() {
		return "CorruptDetection [updateTime=" + updateTime + ", sharePublicKeys=" + Arrays.toString(sharePublicKeys)
				+ "]";
	}

}
