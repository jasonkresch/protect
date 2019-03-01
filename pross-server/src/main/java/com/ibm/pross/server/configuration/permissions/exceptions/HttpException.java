package com.ibm.pross.server.configuration.permissions.exceptions;

public abstract class HttpException extends Exception {

	private static final long serialVersionUID = -8256564936942511699L;

	public abstract int getErrorCode();
	
	public abstract String getErrorMessage();
	
}
