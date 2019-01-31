package com.ibm.pross.server.app.dkgnew.exceptions;

import com.ibm.pross.server.app.dkgnew.AlertLog.ErrorCondition;

public class InvalidCiphertextException extends ErrorConditionException {

	private static final long serialVersionUID = -7484306246167852713L;

	public InvalidCiphertextException() {
		super();
	}
	
	public InvalidCiphertextException(String message) {
		super(message);
	}

	public InvalidCiphertextException(String message, Throwable cause) {
		super(message, cause);
	}

	public InvalidCiphertextException(Throwable cause) {
		super(cause);
	}
	
	@Override
	public ErrorCondition getErrorCondition() {
		return ErrorCondition.InvalidCiphertext;
	}

}
