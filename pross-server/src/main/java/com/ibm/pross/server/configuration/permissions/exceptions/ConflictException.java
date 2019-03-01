package com.ibm.pross.server.configuration.permissions.exceptions;

import com.ibm.pross.server.app.http.HttpStatusCode;

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
