package com.ibm.pross.common.exceptions.http;

public class ConflictException extends HttpException {

	private static final long serialVersionUID = 5701114951079530631L;

	@Override
	public int getErrorCode() {
		return HttpStatusCode.CONFLICT;
	}

	@Override
	public String getErrorMessage() {
		return "Already Exists";
	}
	
}
