package com.ibm.pross.server.dkgnew;

import java.io.Serializable;
import java.util.SortedMap;

import com.ibm.pross.server.messages.Payload;

class ZkpBulkPayload implements Payload, Serializable {

	private static final long serialVersionUID = 7424142805101187480L;
	
	private final SortedMap<Integer, ZeroKnowledgeProof> proofs;

	public ZkpBulkPayload(final SortedMap<Integer, ZeroKnowledgeProof> proofs) {
		this.proofs = proofs;
	}

	@Override
	public OpCode getOpcode() {
		return OpCode.BP;
	}

	public SortedMap<Integer, ZeroKnowledgeProof> getProofs() {
		return proofs;
	}

	@Override
	public String toString() {
		return "ZkpPayload [proof=" + proofs + "]";
	}

}