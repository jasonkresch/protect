package com.ibm.pross.server.app.dkgnew;

import java.io.Serializable;
import java.util.Arrays;

import com.ibm.pross.common.util.crypto.ecc.EcPoint;
import com.ibm.pross.server.messages.Payload;

class PedersonCommitments extends Payload implements Serializable {

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

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + Arrays.hashCode(commitments);
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
		PedersonCommitments other = (PedersonCommitments) obj;
		if (!Arrays.equals(commitments, other.commitments))
			return false;
		return true;
	}
	
	
}