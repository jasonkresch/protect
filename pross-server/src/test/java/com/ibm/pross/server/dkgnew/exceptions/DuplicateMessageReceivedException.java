package com.ibm.pross.server.dkgnew.exceptions;

import com.ibm.pross.server.dkgnew.AlertLog.ErrorCondition;

public class DuplicateMessageReceivedException extends ErrorConditionException {

	private static final long serialVersionUID = -8581941928217098125L;

	public DuplicateMessageReceivedException() {
		super();
	}
	
	public DuplicateMessageReceivedException(String message) {
		super(message);
	}

	@Override
	public ErrorCondition getErrorCondition() {
		return ErrorCondition.DuplicateMessage;
	}

}
