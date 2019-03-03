package com.ibm.pross.common.util.crypto.rsa.threshold.sign.exceptions;

public class BelowThresholdException extends Exception {

	private static final long serialVersionUID = -2513604084683567470L;

	public BelowThresholdException() {
		super();
	}

	public BelowThresholdException(String message, Throwable cause) {
		super(message, cause);
	}

	public BelowThresholdException(String message) {
		super(message);
	}

	public BelowThresholdException(Throwable cause) {
		super(cause);
	}

}
