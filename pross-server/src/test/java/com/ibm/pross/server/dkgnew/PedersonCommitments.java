package com.ibm.pross.server.dkgnew;

import java.io.Serializable;
import java.util.Arrays;

import com.ibm.pross.common.util.crypto.ecc.EcPoint;
import com.ibm.pross.server.messages.Payload;

class PedersonCommitments implements Payload, Serializable {

	private static final long serialVersionUID = -3413167967781971330L;
	private final EcPoint[] commitments;

	public PedersonCommitments(final EcPoint[] commitments) {
		this.commitments = commitments;
	}

	@Override
	public OpCode getOpcode() {
		return OpCode.MS;
	}

	public EcPoint[] getCommitments() {
		return this.commitments;
	}

	@Override
	public String toString() {
		return "PedersonCommitments [commitments=" + Arrays.toString(commitments) + "]";
	}
}