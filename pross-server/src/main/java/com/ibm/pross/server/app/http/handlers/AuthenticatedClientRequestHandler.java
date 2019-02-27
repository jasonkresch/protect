package com.ibm.pross.server.app.http.handlers;

import java.io.IOException;

import com.ibm.pross.server.configuration.permissions.exceptions.BadRequestException;
import com.ibm.pross.server.configuration.permissions.exceptions.ConflictException;
import com.ibm.pross.server.configuration.permissions.exceptions.NotFoundException;
import com.ibm.pross.server.configuration.permissions.exceptions.UnauthorizedException;
import com.sun.net.httpserver.HttpExchange;

@SuppressWarnings("restriction")
public abstract class AuthenticatedClientRequestHandler extends BaseHttpHandler {

	@Override
	public void handleWithExceptions(final HttpExchange exchange)
			throws IOException, UnauthorizedException, NotFoundException, ConflictException, BadRequestException {

		// FIXME: Implement client authentication by checking aspects of the connection
		// E.g., client id in the header, validate signature on request or check the
		// HTTPS info
		final int clientId = 1;

		// Invoke the sub-class's handler with the detected client id
		this.authenticatedClientHandle(exchange, clientId);
	}

	/**
	 * This method is invoked only after the client's request has been
	 * authenticated. If the client fails to be authenticated then clientId will be
	 * null.
	 * 
	 * @param exchange
	 * @param clientId
	 * @throws IOException
	 * @throws NotFoundException
	 * @throws ConflictException
	 * @throws BadRequestException 
	 */
	public abstract void authenticatedClientHandle(final HttpExchange exchange, final Integer clientId)
			throws IOException, UnauthorizedException, NotFoundException, ConflictException, BadRequestException;

}
