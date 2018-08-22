/*
 * Copyright (c) IBM Corporation 2018. All Rights Reserved.
 * Project name: pross
 * This project is licensed under the MIT License, see LICENSE.
 */

package com.ibm.pross.server.messages.payloads;

import com.ibm.pross.common.util.shamir.ShamirShare;
import com.ibm.pross.server.messages.Payload;

public class VssPrivatePayload implements Payload {

	private static final long serialVersionUID = -2962821141936322572L;

	private final ShamirShare shareUpdate;

	public VssPrivatePayload(final ShamirShare shareUpdate) {
		this.shareUpdate = shareUpdate;
	}

	@Override
	public OpCode getOpcode() {
		return OpCode.NA;
	}

	public ShamirShare getShareUpdate() {
		return shareUpdate;
	}

	@Override
	public String toString() {
		return "VssPrivatePayload [shareUpdate=" + shareUpdate + "]";
	}


}
