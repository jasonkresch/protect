package com.ibm.pross.server.configuration.permissions.exceptions;

import com.ibm.pross.server.app.http.HttpStatusCode;

public class UnauthorizedException extends HttpException {

	private static final long serialVersionUID = 8677670782659579794L;

	@Override
	public int getErrorCode() {
		return HttpStatusCode.NOT_AUTHORIZED;
	}

	@Override
	public String getErrorMessage() {
		return "Unauthorized";
	}
	
}
