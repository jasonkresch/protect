package com.ibm.pross.server.dkgnew;

import java.io.Serializable;

import com.ibm.pross.server.messages.Payload;

class ZkpPayload extends Payload implements Serializable {

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

}