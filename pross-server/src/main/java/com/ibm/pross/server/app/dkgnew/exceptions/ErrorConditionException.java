package com.ibm.pross.server.app.dkgnew.exceptions;

import com.ibm.pross.server.app.dkgnew.AlertLog.ErrorCondition;

public abstract class ErrorConditionException extends Exception {

	private static final long serialVersionUID = -4974777689276200898L;
	
	public ErrorConditionException() {
		super();
	}

	public ErrorConditionException(String message) {
		super(message);
	}

	public ErrorConditionException(String message, Throwable cause) {
		super(message, cause);
	}

	public ErrorConditionException(Throwable cause) {
		super(cause);
	}

	public abstract ErrorCondition getErrorCondition();

}
