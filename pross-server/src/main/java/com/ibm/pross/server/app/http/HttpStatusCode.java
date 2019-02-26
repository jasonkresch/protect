package com.ibm.pross.server.app.http;

public class HttpStatusCode {

	public static final int SUCCESS = 200;
	
	// Client errors
	public static final int NOT_FOUND = 404;
	public static final int NOT_AUTHENTICATED = 401;
	public static final int NOT_AUTHORIZED = 403;
	
	// Server errors
	public static final int SERVER_ERROR = 500;
	public static final int OUT_OF_RESOURCES = 503;
}
