package com.ibm.pross.server.app.http.handlers;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;

import com.ibm.pross.server.app.http.HttpStatusCode;
import com.ibm.pross.server.configuration.permissions.UnauthorizedException;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;

@SuppressWarnings("restriction")
public abstract class AuthenticatedClientRequestHandler implements HttpHandler {

	@Override
	public void handle(final HttpExchange exchange) throws IOException {

		// FIXME: Implement client authentication by checking aspects of the connection
		// E.g., client id in the header, validate signature on request or check the
		// HTTPS info
		final int clientId = 0;

		// Invoke the sub-class's handler
		try {
			this.authenticatedClientHandle(exchange, clientId);
		} catch (UnauthorizedException e) {
			final String response = "Unauthorized";
			final byte[] binaryResponse = response.getBytes(StandardCharsets.UTF_8);
			exchange.sendResponseHeaders(HttpStatusCode.NOT_AUTHORIZED, binaryResponse.length);
			try (final OutputStream os = exchange.getResponseBody();) {
				os.write(binaryResponse);
			}
		}
	}

	/**
	 * This method is invoked only after the client's request has been authenticated. If the client fails 
	 * to be authenticated then clientId will be null.
	 * 
	 * @param exchange
	 * @param clientId
	 * @throws IOException
	 */
	public abstract void authenticatedClientHandle(final HttpExchange exchange, final Integer clientId)
			throws IOException, UnauthorizedException;

}
