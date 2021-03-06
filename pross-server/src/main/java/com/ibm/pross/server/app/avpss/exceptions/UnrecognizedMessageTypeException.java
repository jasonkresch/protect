package com.ibm.pross.server.app.avpss.exceptions;

import com.ibm.pross.server.app.avpss.AlertLog.ErrorCondition;

public class UnrecognizedMessageTypeException extends ErrorConditionException {

	private static final long serialVersionUID = -2027492507179206047L;

	public UnrecognizedMessageTypeException() {
		super();
	}
	
	public UnrecognizedMessageTypeException(String message) {
		super(message);
	}

	@Override
	public ErrorCondition getErrorCondition() {
		return ErrorCondition.UnrecognizedMessageType;
	}

}
