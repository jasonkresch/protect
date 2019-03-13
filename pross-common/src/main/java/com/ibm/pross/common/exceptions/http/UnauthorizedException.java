package com.ibm.pross.common.exceptions.http;

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
