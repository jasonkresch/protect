/*
 * Copyright (c) IBM Corporation 2018. All Rights Reserved.
 * Project name: pross
 * This project is licensed under the MIT License, see LICENSE.
 */

package com.ibm.pross.server.messages.payloads.refresh;

import java.util.Set;
import java.util.SortedSet;
import java.util.UUID;

import com.ibm.pross.server.messages.Payload;

public class RefreshAccusations implements Payload {

	private static final long serialVersionUID = -1008668768935824766L;

	// FIXME: Remove this when set hashcode and equality are fixed
	private final UUID messageId = UUID.randomUUID();
	
	private final long updateTime;
	private final SortedSet<Integer> accused;

	public RefreshAccusations(final long updateTime, final SortedSet<Integer> accused) {
		this.updateTime = updateTime;
		this.accused = accused;
	}

	@Override
	public OpCode getOpcode() {
		return OpCode.REFRESH_ACCUSATIONS;
	}

	public long getUpdateTime() {
		return updateTime;
	}

	public Set<Integer> getAccused() {
		return accused;
	}

	@Override
	public String toString() {
		return "RefreshAccusations [updateTime=" + updateTime + ", accused=" + accused + "]";
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
		RefreshAccusations other = (RefreshAccusations) obj;
		if (messageId == null) {
			if (other.messageId != null)
				return false;
		} else if (!messageId.equals(other.messageId))
			return false;
		return true;
	}



	
}
