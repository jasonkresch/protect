/*
 * Copyright (c) IBM Corporation 2018. All Rights Reserved.
 * Project name: pross
 * This project is licensed under the MIT License, see LICENSE.
 */

package com.ibm.pross.server.messages.payloads.reconstruction;

import java.util.Set;
import java.util.SortedSet;

import com.ibm.pross.server.messages.Payload;

public class ReconstructionAccusations implements Payload {

	private static final long serialVersionUID = -8282949906116353394L;

	private final long updateTime;
	private final int corruptShareholder;
	private final SortedSet<Integer> accused;

	public ReconstructionAccusations(final long updateTime, final int coorruptShareholder,
			final SortedSet<Integer> accused) {
		this.updateTime = updateTime;
		this.corruptShareholder = coorruptShareholder;
		this.accused = accused;
	}

	@Override
	public OpCode getOpcode() {
		return OpCode.RECONSTRUCTION_ACCUSATIONS;
	}

	public long getUpdateTime() {
		return updateTime;
	}

	public int getCorruptShareholder() {
		return corruptShareholder;
	}

	public Set<Integer> getAccused() {
		return accused;
	}

	@Override
	public String toString() {
		return "ReconstructionAccusations [updateTime=" + updateTime + ", corruptShareholder=" + corruptShareholder
				+ ", accused=" + accused + "]";
	}

}
