package com.ibm.pross.server.app.dkgnew;

import java.io.Serializable;
import java.util.SortedMap;
import java.util.UUID;

import com.ibm.pross.server.messages.Payload;

class ZkpBulkPayload extends Payload implements Serializable {

	private static final long serialVersionUID = 7424142805101187480L;
	
	// FIXME: Remove this when set hashcode and equality are fixed
	private final UUID messageId = UUID.randomUUID();
	
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

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((messageId == null) ? 0 : messageId.hashCode());
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
		ZkpBulkPayload other = (ZkpBulkPayload) obj;
		if (messageId == null) {
			if (other.messageId != null)
				return false;
		} else if (!messageId.equals(other.messageId))
			return false;
		return true;
	}
	
	

}