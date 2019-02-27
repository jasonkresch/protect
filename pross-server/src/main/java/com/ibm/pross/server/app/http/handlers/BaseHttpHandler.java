package com.ibm.pross.server.app.http.handlers;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;

import com.ibm.pross.server.app.http.HttpStatusCode;
import com.ibm.pross.server.configuration.permissions.exceptions.ConflictException;
import com.ibm.pross.server.configuration.permissions.exceptions.NotFoundException;
import com.ibm.pross.server.configuration.permissions.exceptions.UnauthorizedException;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;

@SuppressWarnings("restriction")
public abstract class BaseHttpHandler implements HttpHandler {

	@Override
	public void handle(final HttpExchange exchange) throws IOException {
		// Invoke the sub-class's handler
		try {
			this.handleWithExceptions(exchange);
		} catch (final UnauthorizedException e) {
			final String response = "403: Unauthorized\n";
			final byte[] binaryResponse = response.getBytes(StandardCharsets.UTF_8);
			exchange.sendResponseHeaders(HttpStatusCode.NOT_AUTHORIZED, binaryResponse.length);
			try (final OutputStream os = exchange.getResponseBody();) {
				os.write(binaryResponse);
			}
		} catch (final NotFoundException e) {
			final String response = "404: Not Found\n";
			final byte[] binaryResponse = response.getBytes(StandardCharsets.UTF_8);
			exchange.sendResponseHeaders(HttpStatusCode.NOT_FOUND, binaryResponse.length);
			try (final OutputStream os = exchange.getResponseBody();) {
				os.write(binaryResponse);
			}
		} catch (final ConflictException e) {
			final String response = "409: Already Exists\n";
			final byte[] binaryResponse = response.getBytes(StandardCharsets.UTF_8);
			exchange.sendResponseHeaders(HttpStatusCode.CONFLICT, binaryResponse.length);
			try (final OutputStream os = exchange.getResponseBody();) {
				os.write(binaryResponse);
			}
		}
	}

	/**
	 * This method catches any exception that might be thrown and returns an
	 * appropriate HTTP status code and error message.
	 * 
	 * @see HttpStatusCode
	 * 
	 * @param exchange
	 * @throws IOException
	 * @throws UnauthorizedException
	 * @throws NotFoundException
	 */
	public abstract void handleWithExceptions(final HttpExchange exchange)
			throws IOException, UnauthorizedException, NotFoundException, ConflictException;
}