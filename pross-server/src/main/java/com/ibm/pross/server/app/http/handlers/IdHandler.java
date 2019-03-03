package com.ibm.pross.server.app.http.handlers;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;

import com.ibm.pross.server.app.http.HttpStatusCode;
import com.ibm.pross.server.configuration.permissions.exceptions.BadRequestException;
import com.ibm.pross.server.configuration.permissions.exceptions.NotFoundException;
import com.ibm.pross.server.configuration.permissions.exceptions.UnauthorizedException;
import com.sun.net.httpserver.HttpExchange;

import bftsmart.reconfiguration.util.sharedconfig.KeyLoader;

/**
 * This handler returns the id of the authenticated client
 */
@SuppressWarnings("restriction")
public class IdHandler extends AuthenticatedClientRequestHandler {

	public IdHandler(final KeyLoader clientKeys) {
		super(clientKeys);
	}

	@Override
	public void authenticatedClientHandle(final HttpExchange exchange, final Integer clientId)
			throws IOException, UnauthorizedException, NotFoundException, BadRequestException {

		// Create response
		final String response;
		if (clientId != null) {
			response = "You have authenticated as Client " + clientId + ".\n";
		} else {
			response = "You have failed to authenticate and are Anonymous.\n";
		}
		final byte[] binaryResponse = response.getBytes(StandardCharsets.UTF_8);

		// Write headers
		exchange.sendResponseHeaders(HttpStatusCode.SUCCESS, binaryResponse.length);

		// Write response
		try (final OutputStream os = exchange.getResponseBody();) {
			os.write(binaryResponse);
		}
	}

}