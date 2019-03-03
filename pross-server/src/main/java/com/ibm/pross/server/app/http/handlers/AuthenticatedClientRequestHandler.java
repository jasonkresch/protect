package com.ibm.pross.server.app.http.handlers;

import java.io.IOException;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;

import com.ibm.pross.server.configuration.permissions.exceptions.BadRequestException;
import com.ibm.pross.server.configuration.permissions.exceptions.ConflictException;
import com.ibm.pross.server.configuration.permissions.exceptions.NotFoundException;
import com.ibm.pross.server.configuration.permissions.exceptions.ResourceUnavailableException;
import com.ibm.pross.server.configuration.permissions.exceptions.UnauthorizedException;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpsExchange;

import bftsmart.reconfiguration.util.sharedconfig.KeyLoader;

@SuppressWarnings("restriction")
public abstract class AuthenticatedClientRequestHandler extends BaseHttpHandler {

	private final KeyLoader clientKeys;

	public AuthenticatedClientRequestHandler(final KeyLoader clientKeys) {
		this.clientKeys = clientKeys;
	}

	@Override
	public void handleWithExceptions(final HttpExchange exchange)
			throws IOException, UnauthorizedException, NotFoundException, ConflictException, BadRequestException, ResourceUnavailableException {

		if (exchange instanceof HttpsExchange) {

			// Get SSL Session
			final HttpsExchange secureExchange = (HttpsExchange) exchange;
			final SSLSession sslSession = secureExchange.getSSLSession();

			final Integer clientId = determineClientIdentity(this.clientKeys, sslSession);

			// Invoke the sub-class's handler with the detected client id
			this.authenticatedClientHandle(exchange, clientId);

		} else {
			throw new RuntimeException("HTTPS is required");
		}
	}

	/**
	 * Attempts to map the end-entity client certificate from the SSLSession to a
	 * known client public key. If it can be mapped will return an integer for that
	 * client. Otherwise will return null.
	 * 
	 * @param clientKeyLoader
	 * @param session
	 * @return
	 */
	private static Integer determineClientIdentity(final KeyLoader clientKeyLoader, final SSLSession sslSession) {

		try {
			final Certificate[] certs = sslSession.getPeerCertificates();
			final X509Certificate clientCertificate = (X509Certificate) certs[0];
			final PublicKey clientPublicKey = clientCertificate.getPublicKey();

			// Attempt to link the public key in the client certificate to a known client
			// key
			return clientKeyLoader.getEntityIndex(clientPublicKey);

		} catch (SSLPeerUnverifiedException e) {
			// The client did not provide a certificate
			return null;
		}
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
	 * @throws ResourceUnavailableException 
	 */
	public abstract void authenticatedClientHandle(final HttpExchange exchange, final Integer clientId)
			throws IOException, UnauthorizedException, NotFoundException, ConflictException, BadRequestException, ResourceUnavailableException;

}
