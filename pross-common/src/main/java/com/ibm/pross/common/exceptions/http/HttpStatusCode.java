package com.ibm.pross.common.exceptions.http;

public class HttpStatusCode {

	public static final int SUCCESS = 200;
	
	// Client errors
	public static final int BAD_REQUEST = 400;
	public static final int NOT_FOUND = 404;
	public static final int NOT_AUTHENTICATED = 401;
	public static final int NOT_AUTHORIZED = 403;
	public static final int CONFLICT = 409;
	
	// Server errors
	public static final int SERVER_ERROR = 500;
	public static final int RESOURCE_UNAVAILABLE = 503;
}
