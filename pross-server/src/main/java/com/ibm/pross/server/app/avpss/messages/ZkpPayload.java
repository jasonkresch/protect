package com.ibm.pross.server.app.avpss.messages;

import java.io.Serializable;

import com.ibm.pross.common.util.crypto.zkp.splitting.ZeroKnowledgeProof;
import com.ibm.pross.server.messages.Payload;

public class ZkpPayload extends Payload implements Serializable {

	private static final long serialVersionUID = -261650921682118631L;

	private final ZeroKnowledgeProof proof;

	public ZkpPayload(final ZeroKnowledgeProof proof) {
		super(OpCode.ZK, proof);
		this.proof = proof;
	}

	public ZeroKnowledgeProof getProof() {
		return proof;
	}

	@Override
	public String toString() {
		return "ZkpPayload [proof=" + proof + "]";
	}
}