package com.ibm.pross.server.app.avpss;

import java.io.Serializable;

import com.ibm.pross.common.util.pvss.PublicSharing;
import com.ibm.pross.server.messages.Payload;

class PublicSharingPayload implements Payload, Serializable {

	private static final long serialVersionUID = -3305552097003223276L;

	private final PublicSharing publicSharing;

	public PublicSharingPayload(final PublicSharing publicSharing) {
		this.publicSharing = publicSharing;
	}

	
	
	public PublicSharing getPublicSharing() {
		return publicSharing;
	}



	@Override
	public OpCode getOpcode() {
		return OpCode.PS;
	}

	@Override
	public String toString() {
		return "PublicSharingPayload [publicSharing=" + publicSharing + "]";
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((publicSharing == null) ? 0 : publicSharing.hashCode());
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
		PublicSharingPayload other = (PublicSharingPayload) obj;
		if (publicSharing == null) {
			if (other.publicSharing != null)
				return false;
		} else if (!publicSharing.equals(other.publicSharing))
			return false;
		return true;
	}

}