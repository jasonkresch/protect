package com.ibm.pross.common.exceptions.http;

public class InternalServerException extends HttpException {

	private static final long serialVersionUID = 2378026284623518499L;

	@Override
	public int getErrorCode() {
		return HttpStatusCode.SERVER_ERROR;
	}

	@Override
	public String getErrorMessage() {
		return "Internal Error";
	}

}
