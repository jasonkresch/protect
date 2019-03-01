package com.ibm.pross.server.configuration.permissions.exceptions;

import com.ibm.pross.server.app.http.HttpStatusCode;

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
