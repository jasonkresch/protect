package com.ibm.pross.server.app.dkgnew;

import java.io.Serializable;
import java.util.Arrays;

import com.ibm.pross.server.messages.Payload;

class Verification implements Payload, Serializable {

	private static final long serialVersionUID = 3964665948810948554L;
	
	private final Boolean[] verificationVector;

	public Verification(final Boolean[] verificationVector) {
		this.verificationVector = verificationVector;
	}

	@Override
	public OpCode getOpcode() {
		return OpCode.VV;
	}

	public Boolean[] getVerificationVector() {
		return this.verificationVector;
	}

	@Override
	public String toString() {
		return "Verification [verificationVector=" + Arrays.toString(verificationVector) + "]";
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + Arrays.hashCode(verificationVector);
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
		Verification other = (Verification) obj;
		if (!Arrays.equals(verificationVector, other.verificationVector))
			return false;
		return true;
	}


}