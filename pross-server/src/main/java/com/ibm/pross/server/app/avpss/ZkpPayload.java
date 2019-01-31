package com.ibm.pross.server.app.avpss;

import java.io.Serializable;

import com.ibm.pross.common.util.crypto.zkp.splitting.ZeroKnowledgeProof;
import com.ibm.pross.server.messages.Payload;

class ZkpPayload implements Payload, Serializable {

	private static final long serialVersionUID = -261650921682118631L;
	
	private final ZeroKnowledgeProof proof;

	public ZkpPayload(final ZeroKnowledgeProof proof) {
		this.proof = proof;
	}

	@Override
	public OpCode getOpcode() {
		return OpCode.ZK;
	}

	public ZeroKnowledgeProof getProof() {
		return proof;
	}

	@Override
	public String toString() {
		return "ZkpPayload [proof=" + proof + "]";
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((proof == null) ? 0 : proof.hashCode());
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
		ZkpPayload other = (ZkpPayload) obj;
		if (proof == null) {
			if (other.proof != null)
				return false;
		} else if (!proof.equals(other.proof))
			return false;
		return true;
	}
	
	

}