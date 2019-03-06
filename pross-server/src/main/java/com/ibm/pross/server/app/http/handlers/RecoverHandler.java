package com.ibm.pross.server.app.http.handlers;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.AbstractMap.SimpleEntry;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;

import com.ibm.pross.common.util.crypto.paillier.PaillierCipher;
import com.ibm.pross.common.util.crypto.paillier.PaillierPrivateKey;
import com.ibm.pross.server.app.avpss.ApvssShareholder;
import com.ibm.pross.server.app.avpss.SharingState;
import com.ibm.pross.server.app.http.HttpRequestProcessor;
import com.ibm.pross.server.app.http.HttpStatusCode;
import com.ibm.pross.server.configuration.permissions.AccessEnforcement;
import com.ibm.pross.server.configuration.permissions.ClientPermissions.Permissions;
import com.ibm.pross.server.configuration.permissions.exceptions.BadRequestException;
import com.ibm.pross.server.configuration.permissions.exceptions.ConflictException;
import com.ibm.pross.server.configuration.permissions.exceptions.NotFoundException;
import com.ibm.pross.server.configuration.permissions.exceptions.ResourceUnavailableException;
import com.ibm.pross.server.configuration.permissions.exceptions.UnauthorizedException;
import com.sun.net.httpserver.HttpExchange;

import bftsmart.reconfiguration.util.sharedconfig.KeyLoader;
import bftsmart.reconfiguration.util.sharedconfig.ServerConfiguration;

/**
 * This handler initiates a share recovery operation for this shareholder.
 * Client's must have a specific authorization to be able to invoke this method.
 * If the secret is not found a 404 is returned. If the client is not authorized
 * a 403 is returned.
 * 
 * This method triggers this server to open HTTPS connections to others servers
 * to obtain encrypted partial contributions to the recovery of the share.
 */
@SuppressWarnings("restriction")
public class RecoverHandler extends AuthenticatedClientRequestHandler {

	public static final Permissions REQUEST_PERMISSION = Permissions.RECOVER;

	// Query name
	public static final String SECRET_NAME_FIELD = "secretName";

	// Fields
	private final AccessEnforcement accessEnforcement;
	private final ServerConfiguration serverConfig;
	private final ConcurrentMap<String, ApvssShareholder> shareholders;
	private final List<X509Certificate> caCerts;
	private final KeyLoader serverKeys;
	private final X509Certificate hostCert;
	private final PrivateKey privateKey;

	public RecoverHandler(final KeyLoader clientKeys, final AccessEnforcement accessEnforcement,
			final ServerConfiguration serverConfig, final ConcurrentMap<String, ApvssShareholder> shareholders,
			final List<X509Certificate> caCerts, final KeyLoader serverKeys, final X509Certificate hostCert,
			final PrivateKey privateKey) {
		super(clientKeys);
		this.shareholders = shareholders;
		this.serverConfig = serverConfig;
		this.accessEnforcement = accessEnforcement;

		// For connecting to and authenticating other servers
		this.caCerts = caCerts;
		this.serverKeys = serverKeys;
		this.hostCert = hostCert;
		this.privateKey = privateKey;
	}

	@Override
	public void authenticatedClientHandle(final HttpExchange exchange, final String username)
			throws IOException, UnauthorizedException, NotFoundException, BadRequestException, ConflictException,
			ResourceUnavailableException {

		// Extract secret name from request
		final String queryString = exchange.getRequestURI().getQuery();
		final Map<String, List<String>> params = HttpRequestProcessor.parseQueryString(queryString);
		final List<String> secretNames = params.get(SECRET_NAME_FIELD);
		if (secretNames == null || secretNames.size() != 1) {
			throw new BadRequestException();
		}
		final String secretName = secretNames.get(0);

		// Perform authentication
		accessEnforcement.enforceAccess(username, secretName, REQUEST_PERMISSION);

		// Do processing
		final ApvssShareholder shareholder = this.shareholders.get(secretName);
		if (shareholder == null) {
			throw new NotFoundException();
		}

		// Create response
		final String response = doShareRecovery(shareholder, secretName);
		final byte[] binaryResponse = response.getBytes(StandardCharsets.UTF_8);

		// Write headers
		// exchange.getResponseHeaders().add("Strict-Transport-Security", "max-age=300;
		// includeSubdomains");
		exchange.sendResponseHeaders(HttpStatusCode.SUCCESS, binaryResponse.length);

		// Write response
		try (final OutputStream os = exchange.getResponseBody();) {
			os.write(binaryResponse);
		}
	}

	private String doShareRecovery(final ApvssShareholder shareholder, final String secretName)
			throws ConflictException, ResourceUnavailableException {

		// This server
		final int serverIndex = shareholder.getIndex();
		final int numShareholders = shareholder.getN();
		final int reconstructionThreshold = shareholder.getK();

		// Current sharing information (where we will rebuild the share
		final long epochNumber = shareholder.getEpoch();
		final SharingState sharingState = shareholder.getSharing(epochNumber);

		if (sharingState.getShare1() != null) {
			// Share already exists
			throw new ConflictException();
		}

		// We create a thread pool with a thread for each task and remote server
		final ExecutorService executor = Executors.newFixedThreadPool(numShareholders - 1);

		// The countdown latch tracks progress towards reaching a threshold
		final CountDownLatch latch = new CountDownLatch(shareholder.getK());
		final AtomicInteger failureCounter = new AtomicInteger(0);
		final int maximumFailures = (numShareholders - reconstructionThreshold);

		// Each task deposits its result into this map after verifying it is correct and
		// consistent
		final ConcurrentHashMap<Long, SimpleEntry<BigInteger, BigInteger>> verifiedResults = new ConcurrentHashMap<>();

		// Do processing
		final long startTime = System.nanoTime();

		// Create a partial result task for everyone except ourselves
		int serverId = 0;
		for (final InetSocketAddress serverAddress : serverConfig.getServerAddresses()) {
			serverId++;
			final String serverIp = serverAddress.getAddress().getHostAddress();
			final int serverPort = HttpRequestProcessor.BASE_HTTP_PORT + serverId;
			final String linkUrl = "https://" + serverIp + ":" + serverPort + "/partial?secretName=" + secretName;

			if (serverId != serverIndex) {
				// Create new task to get the partial result from the server
				executor.submit(new PartialResultTask(serverId, linkUrl, serverIndex, sharingState, verifiedResults,
						latch, failureCounter, maximumFailures));
			}
		}

		try {
			// Once we have K successful responses we can interpolate our share
			latch.await();

			// Check that we have enough results to interpolate the share
			if (failureCounter.get() <= maximumFailures) {

				// When complete, update our share value for the current epoch, and verify
				// consistency of recovery against the existing public verification key
				shareholder.recoverShare(sharingState, new ConcurrentHashMap<>(verifiedResults));

				final long endTime = System.nanoTime();

				// Compute processing time
				final long processingTimeMs = (endTime - startTime) / 1_000_000;

				// Create response
				final String response = "Recovered share #" + serverIndex + " in " + processingTimeMs
						+ " milliseconds for '" + secretName + "' from epoch " + epochNumber + "\n";

				executor.shutdown();

				return response;
			} else {
				executor.shutdown();
				throw new ResourceUnavailableException();
			}
		} catch (InterruptedException e) {
			throw new RuntimeException(e);
		}
	}

	public class PartialResultTask implements Runnable {

		// Remote server info
		private final int remoteServerId;
		private final String requestUrl;

		// State management
		private final int ourServerId;
		private final SharingState sharingState;
		private final ConcurrentHashMap<Long, SimpleEntry<BigInteger, BigInteger>> verifiedResults;
		private final CountDownLatch latch;
		private final AtomicInteger failureCounter;
		private final int maximumFailures;

		public PartialResultTask(final int remoteServerId, final String requestUrl, final int ourServerId,
				final SharingState sharingState,
				final ConcurrentHashMap<Long, SimpleEntry<BigInteger, BigInteger>> verifiedResults,
				final CountDownLatch latch, final AtomicInteger failureCounter, final int maximumFailures) {

			// Remote server info
			this.remoteServerId = remoteServerId;
			this.requestUrl = requestUrl;

			// State management
			this.ourServerId = ourServerId;
			this.sharingState = sharingState;
			this.verifiedResults = verifiedResults;
			this.latch = latch;
			this.failureCounter = failureCounter;
			this.maximumFailures = maximumFailures;
		}

		@Override
		public void run() {

			try {
				System.out.println("Reading encrypted partial share from: " + this.requestUrl);

				// Create HTTPS connection to the remote server
				final URL url = new URL(this.requestUrl);
				final HttpsURLConnection httpsConnection = (HttpsURLConnection) url.openConnection();
				RecoverHandler.this.configureHttps(httpsConnection, remoteServerId, ourServerId);

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
					final Integer serverId = RecoverHandler.this.serverKeys.getEntityIndex(peerPublicKey);
					if (serverId != remoteServerId) {
						System.err.println("Invalid server!!!: was " + serverId + ", expected: " + remoteServerId);
						throw new CertificateException("Invalid peer certificate");
					}

					final String inputLine = bufferedReader.readLine();
					System.out.println("Received encrypted partial: " + inputLine);

					// Parse JSON
					final JSONParser parser = new JSONParser();
					final Object obj = parser.parse(inputLine);
					final JSONObject jsonObject = (JSONObject) obj;
					final Long responder = (Long) jsonObject.get("responder");
					final Long requester = (Long) jsonObject.get("requester");
					final Long epoch = (Long) jsonObject.get("epoch");
					final BigInteger encryptedShare1Part = new BigInteger((String) jsonObject.get("share1_part"));
					final BigInteger encryptedShare2Part = new BigInteger((String) jsonObject.get("share2_part"));
					
					// Verify result
					if ((requester == this.ourServerId) && (responder == this.remoteServerId) && (epoch == this.sharingState.getEpochNumber())) {
						
						// Access our private key
						final PaillierPrivateKey decryptionKey = (PaillierPrivateKey) RecoverHandler.this.serverKeys.getDecryptionKey();
						
						// Decrypt shares
						final BigInteger share1Part = PaillierCipher.decrypt(decryptionKey, encryptedShare1Part);
						final BigInteger share2Part = PaillierCipher.decrypt(decryptionKey, encryptedShare2Part);
						
						// Check against known pedersent commitments from this epoch
						validateConsistency(responder, share1Part, share2Part);
						
						// Store result for later processing
						this.verifiedResults.put(responder, new SimpleEntry<>(share1Part, share2Part));
								
						// Everything checked out, increment successes
						latch.countDown();
					} else {
						throw new Exception("Server " + this.remoteServerId +  " sent inconsistent results");
					}
					
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
				e.printStackTrace();
			}
		}

		private void validateConsistency(final long contributor, BigInteger share1Part, BigInteger share2Part) throws IllegalArgumentException {
		
			// FIXME: Implement this
			
		}
	}

	public void configureHttps(final HttpsURLConnection httpsConnection, final int remoteServerId, final int ourIndex)
			throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException,
			UnrecoverableKeyException, KeyManagementException {

		// Configure SSL context
		final SSLContext sslContext = SSLContext.getInstance(HttpRequestProcessor.TLS_VERSION);

		// Create in-memory key store
		final KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
		final char[] password = "password".toCharArray();
		keyStore.load(null, password);

		// Add the CA certificate for the server
		keyStore.setCertificateEntry("ca-" + remoteServerId, this.caCerts.get(remoteServerId - 1));

		// Add certificate and private key for the server
		final X509Certificate ourCaCert = caCerts.get(ourIndex - 1);
		keyStore.setKeyEntry("host", this.privateKey, password, new X509Certificate[] { hostCert, ourCaCert });

		// Make Key Manager Factory
		final KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
		kmf.init(keyStore, password);

		// Setup the trust manager factory
		final TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509");
		tmf.init(keyStore);

		// Initialize the context
		sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), new SecureRandom());

		// Get the socket factory from the context
		httpsConnection.setSSLSocketFactory(sslContext.getSocketFactory());
	}

}