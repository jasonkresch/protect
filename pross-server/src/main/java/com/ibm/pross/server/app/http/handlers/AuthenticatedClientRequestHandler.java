package com.ibm.pross.server.app.http.handlers;

import java.io.IOException;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;

import com.ibm.pross.server.configuration.permissions.exceptions.BadRequestException;
import com.ibm.pross.server.configuration.permissions.exceptions.ConflictException;
import com.ibm.pross.server.configuration.permissions.exceptions.InternalServerException;
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
	public void handleWithExceptions(final HttpExchange exchange) throws IOException, UnauthorizedException,
			NotFoundException, ConflictException, BadRequestException, ResourceUnavailableException, InternalServerException {

		if (exchange instanceof HttpsExchange) {

			// Get SSL Session
			final HttpsExchange secureExchange = (HttpsExchange) exchange;
			final SSLSession sslSession = secureExchange.getSSLSession();

			final String username = determineUsername(this.clientKeys, sslSession);

			// Invoke the sub-class's handler with the detected entity id
			this.authenticatedClientHandle(exchange, username);

		} else {
			throw new RuntimeException("HTTPS is required");
		}
	}

	/**
	 * Attempts to map the end-entity certificate from the SSLSession to a known
	 * public key from the given key loader. If it can be mapped will return an
	 * integer for that entity. Otherwise will return null.
	 * 
	 * Note this may be used with either a client or server key loader.
	 * 
	 * @param keyLoader
	 * @param session
	 * @return
	 */
	protected static String determineUsername(final KeyLoader keyLoader, final SSLSession sslSession) {

		try {
			final Certificate[] certs = sslSession.getPeerCertificates();
			final X509Certificate peerCertificate = (X509Certificate) certs[0];
			final PublicKey peerPublicKey = peerCertificate.getPublicKey();

			// Attempt to link the public key in the certificate to a known entity's key
			return keyLoader.getUsername(peerPublicKey);

		} catch (SSLPeerUnverifiedException e) {
			// The client did not provide a certificate
			return null;
		}
	}

	/**
	 * This method is invoked only after the requester's request has been
	 * authenticated. If the entity failed to be authenticated then entityId will be
	 * null.
	 * 
	 * @param exchange
	 * @param clientId
	 * @throws IOException
	 * @throws NotFoundException
	 * @throws ConflictException
	 * @throws BadRequestException
	 * @throws ResourceUnavailableException
	 * @throws InternalServerException 
	 */
	public abstract void authenticatedClientHandle(final HttpExchange exchange, final String username)
			throws IOException, UnauthorizedException, NotFoundException, ConflictException, BadRequestException,
			ResourceUnavailableException, InternalServerException;

}
