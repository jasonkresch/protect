package com.ibm.pross.common.exceptions.http;

public class ResourceUnavailableException extends HttpException {

	private static final long serialVersionUID = 6307560392542142178L;

	@Override
	public int getErrorCode() {
		return HttpStatusCode.RESOURCE_UNAVAILABLE;
	}

	@Override
	public String getErrorMessage() {
		return "Resource Temporarily Unavailable";
	}
	
}
