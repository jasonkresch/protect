/*
 * Copyright (c) IBM Corporation 2018. All Rights Reserved.
 * Project name: pross
 * This project is licensed under the MIT License, see LICENSE.
 */

package com.ibm.pross.server.messages.payloads;

import com.ibm.pross.common.util.shamir.ShamirShare;
import com.ibm.pross.server.messages.Payload;

public class VssPrivatePayload extends Payload {

	private static final long serialVersionUID = -2962821141936322572L;

	private final ShamirShare shareUpdate;

	public VssPrivatePayload(final ShamirShare shareUpdate) {
		super(null, null);
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

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((shareUpdate == null) ? 0 : shareUpdate.hashCode());
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
		VssPrivatePayload other = (VssPrivatePayload) obj;
		if (shareUpdate == null) {
			if (other.shareUpdate != null)
				return false;
		} else if (!shareUpdate.equals(other.shareUpdate))
			return false;
		return true;
	}

	

}
