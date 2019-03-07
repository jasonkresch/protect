package com.ibm.pross.server.messages.payloads.apvss;

import com.ibm.pross.common.util.crypto.zkp.splitting.ZeroKnowledgeProof;
import com.ibm.pross.server.messages.Payload;

public class ZkpPayload extends Payload {

	public ZkpPayload(final ZeroKnowledgeProof proof) {
		super(OpCode.ZK, proof);
	}

	public ZeroKnowledgeProof getProof() {
		return (ZeroKnowledgeProof) super.getData();
	}

	@Override
	public String toString() {
		return "ZkpPayload [proof=" + getProof() + "]";
	}
}