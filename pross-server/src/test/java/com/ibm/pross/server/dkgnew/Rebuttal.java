package com.ibm.pross.server.dkgnew;

import java.io.Serializable;

import com.ibm.pross.common.util.shamir.ShamirShare;
import com.ibm.pross.server.messages.Payload;

class Rebuttal extends Payload implements Serializable {

	private static final long serialVersionUID = 9158773360597029949L;

	final int accuserIndex;
	final ShamirShare share1;
	final ShamirShare share2;

	public Rebuttal(final int accuserIndex, final ShamirShare share1, final ShamirShare share2) {
		this.accuserIndex = accuserIndex;
		this.share1 = share1;
		this.share2 = share2;
	}

	@Override
	public OpCode getOpcode() {
		return OpCode.RB;
	}
	
	public int getAccuserIndex() {
		return accuserIndex;
	}

	public ShamirShare getShare1() {
		return this.share1;
	}

	public ShamirShare getShare2() {
		return this.share2;
	}

	@Override
	public String toString() {
		return "Rebuttal [accuserIndex=" + accuserIndex + ", share1=" + share1 + ", share2=" + share2 + "]";
	}


}