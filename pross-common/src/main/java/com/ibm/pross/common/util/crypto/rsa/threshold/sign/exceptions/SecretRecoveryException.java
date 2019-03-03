package com.ibm.pross.common.util.crypto.rsa.threshold.sign.exceptions;

public class SecretRecoveryException extends Exception {

	private static final long serialVersionUID = -435680058331177819L;

	public SecretRecoveryException() {
		super();
	}

	public SecretRecoveryException(String message, Throwable cause) {
		super(message, cause);
	}

	public SecretRecoveryException(String message) {
		super(message);
	}

	public SecretRecoveryException(Throwable cause) {
		super(cause);
	}

}
