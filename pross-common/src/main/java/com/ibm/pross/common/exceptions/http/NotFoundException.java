package com.ibm.pross.common.exceptions.http;

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
