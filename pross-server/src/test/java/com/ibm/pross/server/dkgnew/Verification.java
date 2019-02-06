package com.ibm.pross.server.dkgnew;

import java.io.Serializable;
import java.util.Arrays;

import com.ibm.pross.server.messages.Payload;

class Verification extends Payload implements Serializable {

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


}