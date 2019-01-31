/*
 * Copyright (c) IBM Corporation 2018. All Rights Reserved.
 * Project name: pross
 * This project is licensed under the MIT License, see LICENSE.
 */

package com.ibm.pross.server.messages.payloads.refresh;

import java.util.Arrays;

import com.ibm.pross.common.util.crypto.ecc.EcPoint;
import com.ibm.pross.server.messages.Payload;

public class RefreshVssPublicPayload implements Payload {

	private static final long serialVersionUID = 1184713778927118310L;

	private final long updateTime;
	private final EcPoint[] feldmanValues;

	public RefreshVssPublicPayload(final long updateTime, final EcPoint[] feldmanValues) {
		this.updateTime = updateTime;
		this.feldmanValues = feldmanValues;
	}

	@Override
	public OpCode getOpcode() {
		return OpCode.REFRESH_VSS;
	}

	public long getUpdateTime() {
		return updateTime;
	}

	public EcPoint[] getFeldmanValues() {
		return feldmanValues;
	}

	@Override
	public String toString() {
		return "RefreshVssPublicPayload [updateTime=" + updateTime + ", feldmanValues=" + Arrays.toString(feldmanValues) + "]";
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + Arrays.hashCode(feldmanValues);
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
		RefreshVssPublicPayload other = (RefreshVssPublicPayload) obj;
		if (!Arrays.equals(feldmanValues, other.feldmanValues))
			return false;
		if (updateTime != other.updateTime)
			return false;
		return true;
	}

	
}
