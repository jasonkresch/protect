package com.ibm.pross.server.configuration.permissions.exceptions;

import com.ibm.pross.server.app.http.HttpStatusCode;

public class NotFoundException extends HttpException {

	private static final long serialVersionUID = 581908653276706727L;

	@Override
	public int getErrorCode() {
		return HttpStatusCode.NOT_FOUND;
	}

	@Override
	public String getErrorMessage() {
		return "Not Found";
	}
	
}
