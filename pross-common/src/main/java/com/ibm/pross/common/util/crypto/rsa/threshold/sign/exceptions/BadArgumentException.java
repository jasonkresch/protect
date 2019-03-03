package com.ibm.pross.common.util.crypto.rsa.threshold.sign.exceptions;

public class BadArgumentException extends Exception {

	private static final long serialVersionUID = 2592683107712086975L;

	public BadArgumentException() {
		super();
	}

	public BadArgumentException(String message, Throwable cause) {
		super(message, cause);
	}

	public BadArgumentException(String message) {
		super(message);
	}

	public BadArgumentException(Throwable cause) {
		super(cause);
	}

}
