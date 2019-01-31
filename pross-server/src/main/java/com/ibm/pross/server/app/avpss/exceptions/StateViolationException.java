package com.ibm.pross.server.app.avpss.exceptions;

import com.ibm.pross.server.app.avpss.AlertLog.ErrorCondition;

public class StateViolationException extends ErrorConditionException {

	private static final long serialVersionUID = 3515964453168981538L;

	public StateViolationException() {
		super();
	}
	
	public StateViolationException(String message) {
		super(message);
	}

	@Override
	public ErrorCondition getErrorCondition() {
		return ErrorCondition.StateViolation;
	}

}
