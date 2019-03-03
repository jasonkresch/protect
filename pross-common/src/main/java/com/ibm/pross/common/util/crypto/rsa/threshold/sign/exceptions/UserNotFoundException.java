package com.ibm.pross.common.util.crypto.rsa.threshold.sign.exceptions;

public class UserNotFoundException extends Exception {

	private static final long serialVersionUID = 4353261671618212113L;

	public UserNotFoundException() {
		super();
	}

	public UserNotFoundException(String message, Throwable cause) {
		super(message, cause);
	}

	public UserNotFoundException(String message) {
		super(message);
	}

	public UserNotFoundException(Throwable cause) {
		super(cause);
	}

}
