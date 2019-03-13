package com.ibm.pross.server.app.http.handlers;

import java.io.IOException;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;

import com.ibm.pross.common.config.KeyLoader;
import com.ibm.pross.common.exceptions.http.BadRequestException;
import com.ibm.pross.common.exceptions.http.ConflictException;
import com.ibm.pross.common.exceptions.http.NotFoundException;
import com.ibm.pross.common.exceptions.http.ResourceUnavailableException;
import com.ibm.pross.common.exceptions.http.UnauthorizedException;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpsExchange;

@SuppressWarnings("restriction")
public abstract class AuthenticatedServerRequestHandler extends BaseHttpHandler {

	private final KeyLoader serverKeys;

	public AuthenticatedServerRequestHandler(final KeyLoader serverKeys) {
		this.serverKeys = serverKeys;
	}

	@Override
	public void handleWithExceptions(final HttpExchange exchange) throws IOException, UnauthorizedException,
			NotFoundException, ConflictException, BadRequestException, ResourceUnavailableException {

		if (exchange instanceof HttpsExchange) {

			// Get SSL Session
			final HttpsExchange secureExchange = (HttpsExchange) exchange;
			final SSLSession sslSession = secureExchange.getSSLSession();

			final Integer entityId = determineServerIdentity(this.serverKeys, sslSession);

			// Invoke the sub-class's handler with the detected entity id
			this.authenticatedServerHandle(exchange, entityId);

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
	protected static Integer determineServerIdentity(final KeyLoader keyLoader, final SSLSession sslSession) {

		try {
			final Certificate[] certs = sslSession.getPeerCertificates();
			final X509Certificate peerCertificate = (X509Certificate) certs[0];
			final PublicKey peerPublicKey = peerCertificate.getPublicKey();

			// Attempt to link the public key in the certificate to a known entity's key
			return keyLoader.getEntityIndex(peerPublicKey);

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
	 */
	public abstract void authenticatedServerHandle(final HttpExchange exchange, final Integer serverId)
			throws IOException, UnauthorizedException, NotFoundException, ConflictException, BadRequestException,
			ResourceUnavailableException;

}
