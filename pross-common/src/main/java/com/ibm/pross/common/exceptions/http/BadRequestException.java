package com.ibm.pross.common.exceptions.http;

public class BadRequestException extends HttpException {

	private static final long serialVersionUID = 8713317552372781834L;

	@Override
	public int getErrorCode() {
		return HttpStatusCode.BAD_REQUEST;
	}

	@Override
	public String getErrorMessage() {
		return "Bad Request";
	}
	
}
