/*
 * Copyright (c) IBM Corporation 2018. All Rights Reserved.
 * Project name: pross
 * This project is licensed under the MIT License, see LICENSE.
 */

package com.ibm.pross.server.messages.payloads.reconstruction;

import com.ibm.pross.common.util.shamir.ShamirShare;
import com.ibm.pross.server.messages.Payload;

public class ReconstructionContribution implements Payload {

	private static final long serialVersionUID = 3484871732240190747L;

	private final long updateTime;
	private final ShamirShare shareUpdate;

	public ReconstructionContribution(final long timePeriod, final ShamirShare shareUpdate) {
		this.updateTime = timePeriod;
		this.shareUpdate = shareUpdate;
	}

	@Override
	public OpCode getOpcode() {
		return OpCode.RECONSTRUCTION_CONTRIBUTION;
	}

	public long getUpdateTime() {
		return updateTime;
	}

	public ShamirShare getShareUpdate() {
		return shareUpdate;
	}

	@Override
	public String toString() {
		return "ReconstructionContribution [updateTime=" + updateTime + ", shareUpdate=" + shareUpdate + "]";
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((shareUpdate == null) ? 0 : shareUpdate.hashCode());
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
		ReconstructionContribution other = (ReconstructionContribution) obj;
		if (shareUpdate == null) {
			if (other.shareUpdate != null)
				return false;
		} else if (!shareUpdate.equals(other.shareUpdate))
			return false;
		if (updateTime != other.updateTime)
			return false;
		return true;
	}

	
}
