/*
 * Copyright (c) IBM Corporation 2018. All Rights Reserved.
 * Project name: pross
 * This project is licensed under the MIT License, see LICENSE.
 */

package com.ibm.pross.server.messages.payloads.reconstruction;

import java.util.Set;
import java.util.SortedSet;
import java.util.UUID;

import com.ibm.pross.server.messages.Payload;

public class ReconstructionAccusations extends Payload {

	private static final long serialVersionUID = -8282949906116353394L;

	// FIXME: Remove this when set hashcode and equality are fixed
	private final UUID messageId = UUID.randomUUID();
	
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

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((messageId == null) ? 0 : messageId.hashCode());
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
		ReconstructionAccusations other = (ReconstructionAccusations) obj;
		if (messageId == null) {
			if (other.messageId != null)
				return false;
		} else if (!messageId.equals(other.messageId))
			return false;
		return true;
	}


	

}
