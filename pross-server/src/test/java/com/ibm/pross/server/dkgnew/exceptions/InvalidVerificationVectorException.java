package com.ibm.pross.server.dkgnew.exceptions;

import com.ibm.pross.server.dkgnew.AlertLog.ErrorCondition;

public class InvalidVerificationVectorException extends ErrorConditionException {

	private static final long serialVersionUID = 6464057978773522987L;

	public InvalidVerificationVectorException() {
		super();
	}
	
	public InvalidVerificationVectorException(String message) {
		super(message);
	}

	@Override
	public ErrorCondition getErrorCondition() {
		return ErrorCondition.InvalidVerificationVector;
	}

}
