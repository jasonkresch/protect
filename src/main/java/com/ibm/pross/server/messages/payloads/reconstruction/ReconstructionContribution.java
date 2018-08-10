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

}
