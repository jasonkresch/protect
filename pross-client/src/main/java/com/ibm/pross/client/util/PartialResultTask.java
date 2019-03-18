package com.ibm.pross.client.util;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URL;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicInteger;

import javax.net.ssl.HttpsURLConnection;

public abstract class PartialResultTask implements Runnable {

	// Creator class
	private final BaseClient baseClient;

	// Remote server info
	private final int remoteServerId;
	private final String requestUrl;

	// State management
	private final CountDownLatch latch;
	private final AtomicInteger failureCounter;
	private final int maximumFailures;

	public PartialResultTask(final BaseClient baseClient, final int remoteServerId, final String requestUrl, final List<Object> verifiedResults,
			final CountDownLatch latch, final AtomicInteger failureCounter, final int maximumFailures) {

		this.baseClient = baseClient;
		// Remote server info
		this.remoteServerId = remoteServerId;
		this.requestUrl = requestUrl;

		// State management
		this.latch = latch;
		this.failureCounter = failureCounter;
		this.maximumFailures = maximumFailures;
	}

	@Override
	public void run() {

		try {
			// Create HTTPS connection to the remote server
			final URL url = new URL(this.requestUrl);
			final HttpsURLConnection httpsConnection = (HttpsURLConnection) url.openConnection();
			this.baseClient.configureHttps(httpsConnection, remoteServerId);

			// Configure timeouts and method
			httpsConnection.setRequestMethod("GET");
			httpsConnection.setConnectTimeout(10_000);
			httpsConnection.setReadTimeout(10_000);

			httpsConnection.connect();

			// Read data from it
			try (final InputStream inputStream = httpsConnection.getInputStream();
					final InputStreamReader inputStreamReader = new InputStreamReader(inputStream);
					final BufferedReader bufferedReader = new BufferedReader(inputStreamReader);) {

				// Verify server identity is what we expect
				final Certificate[] certs = httpsConnection.getServerCertificates();
				final X509Certificate peerCertificate = (X509Certificate) certs[0];
				final PublicKey peerPublicKey = peerCertificate.getPublicKey();

				// Attempt to link the public key in the certificate to a known entity's key
				final Integer serverId = this.baseClient.serverKeys.getEntityIndex(peerPublicKey);
				if (serverId != remoteServerId) {
					System.err.println("Invalid server!!!: was " + serverId + ", expected: " + remoteServerId);
					throw new CertificateException("Invalid peer certificate");
				}

				final String inputLine = bufferedReader.readLine();

				// Parse and process
				this.parseJsonResult(inputLine);

			}

		} catch (Exception e) {
			// Increment failure counter
			final int numFailures = this.failureCounter.incrementAndGet();

			// Check if there have been too many failures to succeed
			if (numFailures == (maximumFailures + 1)) { // n - k + 1
				while (latch.getCount() > 0) {
					latch.countDown();
				}
			}
			System.err.println("Exception from server #" + remoteServerId + ": " + e.getMessage());
		}
	}

	protected abstract void parseJsonResult(final String jsonString) throws Exception;
}