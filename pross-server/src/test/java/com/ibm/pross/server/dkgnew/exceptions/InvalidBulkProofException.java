package com.ibm.pross.server.dkgnew.exceptions;

import com.ibm.pross.server.dkgnew.AlertLog.ErrorCondition;

public class InvalidBulkProofException extends ErrorConditionException {

	private static final long serialVersionUID = 186226719206482661L;

	public InvalidBulkProofException() {
		super();
	}
	
	public InvalidBulkProofException(String message) {
		super(message);
	}

	@Override
	public ErrorCondition getErrorCondition() {
		return ErrorCondition.InvalidBulkProof;
	}

}
