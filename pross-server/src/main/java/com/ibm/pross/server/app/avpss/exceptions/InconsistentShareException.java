package com.ibm.pross.server.app.avpss.exceptions;

import com.ibm.pross.server.app.avpss.AlertLog.ErrorCondition;

public class InconsistentShareException extends ErrorConditionException {

	private static final long serialVersionUID = 4684735617563812307L;

	public InconsistentShareException() {
		super();
	}
	
	public InconsistentShareException(String message) {
		super(message);
	}

	@Override
	public ErrorCondition getErrorCondition() {
		return ErrorCondition.InvalidShareContribution;
	}

}
