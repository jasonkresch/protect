package com.ibm.pross.server.app.http.handlers;

import java.io.IOException;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;

@SuppressWarnings("restriction")
public abstract class AuthenticatedServerRequestHandler implements HttpHandler {

	@Override
	public void handle(final HttpExchange exchange) throws IOException {

		// FIXME: Implement server authentication by checking aspects of the connection
		// E.g., server id in the header, validate signature on request or check the
		// HTTPS info
		final int serverId = 0;

		// Invoke the sub-class's handler
		this.authenticatedServerHandle(exchange, serverId);
	}

	/**
	 * This method is invoked only after the server's request has been authenticated. If the server fails 
	 * to be authenticated then serverId will be null.
	 * 
	 * @param exchange
	 * @param clientId
	 * @throws IOException
	 */
	public abstract void authenticatedServerHandle(final HttpExchange exchange, final Integer serverId)
			throws IOException;

}
