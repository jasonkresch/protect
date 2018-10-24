package com.ibm.pross.server.dkgnew.exceptions;

import com.ibm.pross.server.dkgnew.AlertLog.ErrorCondition;

public class InvalidZeroKnowledgeProofException extends ErrorConditionException {

	private static final long serialVersionUID = 6075576190255160083L;
	
	public InvalidZeroKnowledgeProofException() {
		super();
	}
	
	public InvalidZeroKnowledgeProofException(String message) {
		super(message);
	}

	@Override
	public ErrorCondition getErrorCondition() {
		return ErrorCondition.InvalidProof;
	}

}
