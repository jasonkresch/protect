package com.ibm.pross.server.app.dkgnew;

import java.io.Serializable;

import com.ibm.pross.common.util.shamir.ShamirShare;
import com.ibm.pross.server.messages.Payload;

class Shares implements Payload, Serializable {

	private static final long serialVersionUID = 9158773360597029949L;

	final ShamirShare share1;
	final ShamirShare share2;

	public Shares(final ShamirShare share1, final ShamirShare share2) {
		this.share1 = share1;
		this.share2 = share2;
	}

	@Override
	public OpCode getOpcode() {
		return OpCode.MS;
	}

	public ShamirShare getShare1() {
		return this.share1;
	}

	public ShamirShare getShare2() {
		return this.share2;
	}

	@Override
	public String toString() {
		return "Shares [share1=" + share1 + ", share2=" + share2 + "]";
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((share1 == null) ? 0 : share1.hashCode());
		result = prime * result + ((share2 == null) ? 0 : share2.hashCode());
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
		Shares other = (Shares) obj;
		if (share1 == null) {
			if (other.share1 != null)
				return false;
		} else if (!share1.equals(other.share1))
			return false;
		if (share2 == null) {
			if (other.share2 != null)
				return false;
		} else if (!share2.equals(other.share2))
			return false;
		return true;
	}
	
	
}