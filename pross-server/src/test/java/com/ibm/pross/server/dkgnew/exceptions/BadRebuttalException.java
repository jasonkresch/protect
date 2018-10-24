package com.ibm.pross.server.dkgnew.exceptions;

import com.ibm.pross.server.dkgnew.AlertLog.ErrorCondition;

public class BadRebuttalException extends ErrorConditionException {

	private static final long serialVersionUID = -3157258880471578280L;

	public BadRebuttalException() {
		super();
	}
	
	public BadRebuttalException(String message) {
		super(message);
	}

	@Override
	public ErrorCondition getErrorCondition() {
		return ErrorCondition.BadRebuttal;
	}

}
