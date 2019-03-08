package com.ibm.pross.client;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.net.URL;
import java.nio.file.Files;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.AbstractMap.SimpleEntry;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Collectors;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;

import com.ibm.pross.common.CommonConfiguration;
import com.ibm.pross.common.DerivationResult;
import com.ibm.pross.common.util.crypto.ecc.EcPoint;
import com.ibm.pross.common.util.crypto.rsa.threshold.sign.exceptions.BelowThresholdException;
import com.ibm.pross.common.util.serialization.Pem;
import com.ibm.pross.common.util.shamir.Polynomials;
import com.ibm.pross.server.app.http.HttpRequestProcessor;
import com.ibm.pross.server.configuration.permissions.exceptions.ResourceUnavailableException;
import com.ibm.pross.server.util.EciesEncryption;

import bftsmart.reconfiguration.util.sharedconfig.KeyLoader;
import bftsmart.reconfiguration.util.sharedconfig.ServerConfiguration;
import bftsmart.reconfiguration.util.sharedconfig.ServerConfigurationLoader;
import net.i2p.crypto.eddsa.EdDSASecurityProvider;

/**
 * Performs ECIES (Elliptic Curve based ElGamal Encryption and Decryption of
 * files used a distributed secret key)
 */
public class EciesEncryptionClient {

	static {
		Security.addProvider(new BouncyCastleProvider());
		Security.addProvider(new EdDSASecurityProvider());
	}

	// Default paths
	public static String CONFIG_FILENAME = "server/common.config";
	public static String SERVER_KEYS_DIRECTORY = "server/keys";
	public static String CLIENT_DIRECTORY = "client";
	public static String CLIENT_KEYS_DIRECTORY = "client/keys";
	public static String CA_DIRECTORY = "ca";
	public static String CERTS_DIRECTORY = "certs";

	// For connecting to servers
	private final ServerConfiguration serverConfiguration;

	// For authenticating the servers
	private final List<X509Certificate> caCertificates;
	private final KeyLoader serverKeys;

	// For loading our own private key and certificate
	private final X509Certificate clientCertificate;
	private final PrivateKey clientTlsKey;

	// Parameters of operation
	private final String secretName;
	private final File inputFile;
	private final File outputFile;

	public EciesEncryptionClient(final ServerConfiguration serverConfiguration,
			final List<X509Certificate> caCertificates, final KeyLoader serverKeys,
			final X509Certificate clientCertificate, PrivateKey clientTlsKey, final String secretName,
			final File inputFile, final File outputFile, final boolean encrypt) {
		this.serverConfiguration = serverConfiguration;
		this.caCertificates = caCertificates;
		this.serverKeys = serverKeys;
		this.clientCertificate = clientCertificate;
		this.clientTlsKey = clientTlsKey;
		this.secretName = secretName;
		this.inputFile = inputFile;
		this.outputFile = outputFile;
	}

	public void encryptFile() throws BadPaddingException, IllegalBlockSizeException, ClassNotFoundException,
			IOException, ResourceUnavailableException, BelowThresholdException {

		// Print status
		System.out.println("-----------------------------------------------------------");
		System.out.println("Beginning encryption of file: " + this.inputFile);

		// Get public key and current epoch from the server
		System.out.print("Accessing public key for secret: " + this.secretName + "... ");
		final SimpleEntry<EcPoint, Long> publicKeyAndEpoch = this.getServerPublicKey(secretName);
		System.out.println(" (done)");
		final EcPoint publicKey = publicKeyAndEpoch.getKey();
		final long currentEpoch = publicKeyAndEpoch.getValue();
		System.out.println("Public key for secret:    " + publicKey);
		System.out.println("Current epoch for secret: " + currentEpoch);
		System.out.println();

		// Reading
		System.out.print("Reading input file: " + this.inputFile + "... ");
		final byte[] plaintextData = Files.readAllBytes(inputFile.toPath());
		System.out.println(" (done)");
		System.out.println("Read " + plaintextData.length + " bytes.");
		System.out.println();

		// Perform ECIES encryption
		System.out.print("Performing ECIES encryption of file content... ");
		final byte[] ciphertext = EciesEncryption.encrypt(plaintextData, publicKey);
		System.out.println(" (done)");
		System.out.println("Encrypted length " + ciphertext.length + " bytes.");
		System.out.println();

		// Write ciphertext to output file
		System.out.print("Writing ciphertext to file: " + this.outputFile + "... ");
		Files.write(this.outputFile.toPath(), ciphertext);
		System.out.println(" (done)");
		System.out.println("Wrote " + ciphertext.length + " bytes.");
		System.out.println();

		System.out.println("Done.");
		
		
		final EcPoint test = this.exponentiatePoint(CommonConfiguration.g, currentEpoch);
		System.out.println("test public key: " + test);
	}

	public void decryptFile() throws BadPaddingException, IllegalBlockSizeException, ClassNotFoundException,
			IOException, ResourceUnavailableException, BelowThresholdException {

		// Print status
		System.out.println("-----------------------------------------------------------");
		System.out.println("Beginning decryption of file: " + this.inputFile);

		// Reading ciphertext
		System.out.print("Reading input file: " + this.inputFile + "... ");
		final byte[] ciphertextData = Files.readAllBytes(inputFile.toPath());
		System.out.println(" (done)");
		System.out.println("Read " + ciphertextData.length + " bytes of ciphertext.");
		System.out.println();

		// Extract public value from ciphertext
		System.out.print("Extracting public value from ciphertext: " + this.inputFile + "... ");
		final EcPoint publicValue = EciesEncryption.getPublicValue(ciphertextData);
		System.out.println(" (done)");
		System.out.println("Public Value is: " + publicValue);
		System.out.println();

		// Get public key and current epoch from the server
		System.out.print("Accessing public key for secret: " + this.secretName + "... ");
		final SimpleEntry<EcPoint, Long> publicKeyAndEpoch = this.getServerPublicKey(secretName);
		System.out.println(" (done)");
		final EcPoint publicKey = publicKeyAndEpoch.getKey();
		final long currentEpoch = publicKeyAndEpoch.getValue();
		System.out.println("Public key for secret:    " + publicKey);
		System.out.println("Current epoch for secret: " + currentEpoch);
		System.out.println();

		// Get public key and current epoch from the server
		System.out.print("Performing threshold exponentiation on public value using: " + this.secretName + "... ");
		final EcPoint exponentiationResult = this.exponentiatePoint(publicValue, currentEpoch);
		System.out.println(" (done)");
		System.out.println("Shared secret obtained:    " + exponentiationResult);
		System.out.println();

		// Perform ECIES decryption
		System.out.print("Performing ECIES decryption of file content... ");
		final byte[] plaintext = EciesEncryption.decrypt(ciphertextData, exponentiationResult);
		System.out.println(" (done)");
		System.out.println("Plaintext length " + plaintext.length + " bytes.");
		System.out.println();

		// Write plaintext to output file
		System.out.print("Writing plaintext to file: " + this.outputFile + "... ");
		Files.write(this.outputFile.toPath(), plaintext);
		System.out.println(" (done)");
		System.out.println("Wrote " + plaintext.length + " bytes.");
		System.out.println();

		System.out.println("Done.");

	}

	public static void main(final String args[]) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException,
			CertificateException, BadPaddingException, IllegalBlockSizeException, ClassNotFoundException,
			ResourceUnavailableException, BelowThresholdException {

		// Parse arguments
		if (args.length < 6) {
			System.err.println("USAGE: config-dir username secretname [ENCRYPT/DECRYPT] input-file output-file");
			System.exit(-1);
		}
		final File baseDirectory = new File(args[0]);
		final String username = args[1];
		final String secretName = args[2];
		final boolean encrypt = "ENCRYPT".equalsIgnoreCase(args[3]);
		final File inputFile = new File(args[4]);
		final File outputFile = new File(args[5]);

		if (!inputFile.exists()) {
			System.err.println("Input file does not exist: " + inputFile.getAbsolutePath());
			System.exit(-1);
		}

		// Load server configuration (learn n and k)
		final File configFile = new File(baseDirectory, CONFIG_FILENAME);
		final ServerConfiguration configuration = ServerConfigurationLoader.load(configFile);
		System.out.println(configuration);

		// TODO: Get these directly from the shareholder responses
		// final int n = configuration.getNumServers();
		// final int k = configuration.getReconstructionThreshold();

		// Load server keys
		final File keysDirectory = new File(baseDirectory, SERVER_KEYS_DIRECTORY);
		final KeyLoader serverKeys = new KeyLoader(keysDirectory, configuration.getNumServers(), null);

		// Load client certificate
		final File clientDirectory = new File(baseDirectory, CLIENT_DIRECTORY);
		final File certDirectory = new File(clientDirectory, CERTS_DIRECTORY);
		final File clientCertificateFile = new File(certDirectory, "cert-" + username);
		final X509Certificate clientCertificate = Pem.loadCertificateFromFile(clientCertificateFile);

		// Load client key
		final File clientKeysDirectory = new File(baseDirectory, CLIENT_KEYS_DIRECTORY);
		final File clientKeysFile = new File(clientKeysDirectory, "private-" + username);
		final PrivateKey clientPrivateKey = (PrivateKey) Pem.loadKeyFromFile(clientKeysFile);

		// Load CA certificates
		final File caDirectory = new File(baseDirectory, CA_DIRECTORY);
		final List<X509Certificate> caCerts = new ArrayList<>();
		for (int i = 1; i <= configuration.getNumServers(); i++) {
			final File caCertificateFile = new File(caDirectory, "ca-cert-server-" + i + ".pem");
			caCerts.add(Pem.loadCertificateFromFile(caCertificateFile));
		}
		final File caCertificateFile = new File(caDirectory, "ca-cert-clients.pem");
		caCerts.add(Pem.loadCertificateFromFile(caCertificateFile));

		// Create encryption client
		final EciesEncryptionClient encryptionClient = new EciesEncryptionClient(configuration, caCerts, serverKeys,
				clientCertificate, clientPrivateKey, secretName, inputFile, outputFile, encrypt);

		// Perform operation
		if (encrypt) {
			encryptionClient.encryptFile();
		} else {
			encryptionClient.decryptFile();
		}
	}

	private static DerivationResult createDerivationResult(Object obj) {
		return (DerivationResult) obj;
	}

	/**
	 * Interacts with the servers to exponentiate a point for the given secret
	 * 
	 * @param inputPoint
	 * @return
	 * @throws ResourceUnavailableException
	 */
	private EcPoint exponentiatePoint(final EcPoint inputPoint, final long expectedEpoch)
			throws ResourceUnavailableException {

		// Server configuration
		final int numShareholders = this.serverConfiguration.getNumServers();
		final int reconstructionThreshold = this.serverConfiguration.getReconstructionThreshold();

		// We create a thread pool with a thread for each task and remote server
		final ExecutorService executor = Executors.newFixedThreadPool(numShareholders - 1);

		// The countdown latch tracks progress towards reaching a threshold
		final CountDownLatch latch = new CountDownLatch(reconstructionThreshold);
		final AtomicInteger failureCounter = new AtomicInteger(0);
		final int maximumFailures = (numShareholders - reconstructionThreshold);

		// Each task deposits its result into this map after verifying it is correct and
		// consistent
		// TODO: Add verification via proofs
		final List<Object> verifiedResults = Collections.synchronizedList(new ArrayList<>());

		// Create a partial result task for everyone except ourselves
		int serverId = 0;
		for (final InetSocketAddress serverAddress : this.serverConfiguration.getServerAddresses()) {
			serverId++;
			final String serverIp = serverAddress.getAddress().getHostAddress();
			final int serverPort = HttpRequestProcessor.BASE_HTTP_PORT + serverId;
			final String linkUrl = "https://" + serverIp + ":" + serverPort + "/exponentiate?secretName="
					+ this.secretName + "&x=" + inputPoint.getX() + "&y=" + inputPoint.getY() + "&json=true";

			final int thisServerId = serverId;

			// Create new task to get the partial exponentiation result from the server
			executor.submit(
					new PartialResultTask(serverId, linkUrl, verifiedResults, latch, failureCounter, maximumFailures) {
						@Override
						void parseJsonResult(final String json) throws Exception {

							// Parse JSON
							final JSONParser parser = new JSONParser();
							final Object obj = parser.parse(json);
							final JSONObject jsonObject = (JSONObject) obj;
							final Long responder = (Long) jsonObject.get("responder");
							final long epoch = (Long) jsonObject.get("epoch");
							final JSONArray resultPoint = (JSONArray) jsonObject.get("result_point");
							final BigInteger x = new BigInteger((String) resultPoint.get(0));
							final BigInteger y = new BigInteger((String) resultPoint.get(1));

							// Verify result
							// TODO: Separate results by their epoch, wait for enough results of the same
							// epoch
							// TOOD: Implement retry if epoch mismatch and below threshold
							if ((responder == thisServerId) && (epoch == expectedEpoch)) {

								// FIXME: Do verification of the results (using proofs)
								final EcPoint partialResult = new EcPoint(x, y);

								// Store result for later processing
								verifiedResults.add(new DerivationResult(BigInteger.valueOf(responder), partialResult));

								// Everything checked out, increment successes
								latch.countDown();
							} else {
								throw new Exception("Server " + thisServerId
										+ " sent inconsistent results (likely during epoch change)");
							}

						}
					});
		}

		try {
			// Once we have K successful responses we can interpolate our share
			latch.await();

			// Check that we have enough results to interpolate the share
			if (failureCounter.get() <= maximumFailures) {

				List<DerivationResult> results = verifiedResults.stream().map(obj -> createDerivationResult(obj))
						.collect(Collectors.toList());

				// When complete, interpolate the result at zero (where the secret lies)
				final EcPoint interpolatedResult = Polynomials.interpolateExponents(results, reconstructionThreshold,
						0);
				executor.shutdown();

				return interpolatedResult;
			} else {
				executor.shutdown();
				throw new ResourceUnavailableException();
			}
		} catch (InterruptedException e) {
			throw new RuntimeException(e);
		}
	}

	/**
	 * Interacts with the servers to determine the public key of the secret (by
	 * majority vote)
	 * 
	 * @param inputPoint
	 * @return
	 * @throws ResourceUnavailableException
	 * @throws BelowThresholdException
	 */
	@SuppressWarnings("unchecked")
	private SimpleEntry<EcPoint, Long> getServerPublicKey(final String secretName)
			throws ResourceUnavailableException, BelowThresholdException {

		// Server configuration
		final int numShareholders = this.serverConfiguration.getNumServers();
		final int reconstructionThreshold = this.serverConfiguration.getReconstructionThreshold();

		// We create a thread pool with a thread for each task and remote server
		final ExecutorService executor = Executors.newFixedThreadPool(numShareholders - 1);

		// The countdown latch tracks progress towards reaching a threshold
		final CountDownLatch latch = new CountDownLatch(reconstructionThreshold);
		final AtomicInteger failureCounter = new AtomicInteger(0);
		final int maximumFailures = (numShareholders - reconstructionThreshold);

		// Each task deposits its result into this map after verifying it is correct and
		// consistent
		// TODO: Add verification via proofs
		final List<Object> collectedResults = Collections.synchronizedList(new ArrayList<>());

		// Create a partial result task for everyone except ourselves
		int serverId = 0;
		for (final InetSocketAddress serverAddress : this.serverConfiguration.getServerAddresses()) {
			serverId++;
			final String serverIp = serverAddress.getAddress().getHostAddress();
			final int serverPort = HttpRequestProcessor.BASE_HTTP_PORT + serverId;
			final String linkUrl = "https://" + serverIp + ":" + serverPort + "/info?secretName=" + this.secretName
					+ "&json=true";

			final int thisServerId = serverId;

			// Create new task to get the secret info from the server
			executor.submit(
					new PartialResultTask(serverId, linkUrl, collectedResults, latch, failureCounter, maximumFailures) {
						@Override
						void parseJsonResult(final String json) throws Exception {

							// Parse JSON
							final JSONParser parser = new JSONParser();
							final Object obj = parser.parse(json);
							final JSONObject jsonObject = (JSONObject) obj;
							final Long responder = (Long) jsonObject.get("responder");
							final long epoch = (Long) jsonObject.get("epoch");
							final JSONArray resultPoint = (JSONArray) jsonObject.get("public_key");
							final BigInteger x = new BigInteger((String) resultPoint.get(0));
							final BigInteger y = new BigInteger((String) resultPoint.get(1));

							// Store parsed result
							if ((responder == thisServerId)) {

								final EcPoint publicKey = new EcPoint(x, y);

								// Store result for later processing
								collectedResults.add(new SimpleEntry<EcPoint, Long>(publicKey, epoch));

								// Everything checked out, increment successes
								latch.countDown();
							} else {
								throw new Exception("Server " + thisServerId + " sent inconsistent results");
							}

						}
					});
		}

		try {
			// Once we have K successful responses we can interpolate our share
			latch.await();

			// Check that we have enough results to interpolate the share
			if (failureCounter.get() <= maximumFailures) {

				executor.shutdown();

				return (SimpleEntry<EcPoint, Long>) getConsistentConfiguration(collectedResults,
						reconstructionThreshold);
			} else {
				executor.shutdown();
				throw new ResourceUnavailableException();
			}
		} catch (InterruptedException e) {
			throw new RuntimeException(e);
		}
	}

	public static Object getConsistentConfiguration(final Collection<Object> configurationData, int threshold)
			throws BelowThresholdException {

		// Count up the number of consistencies among the configurations
		final Map<Object, Integer> voteTracker = new HashMap<>();
		for (final Object object : configurationData) {
			if (!voteTracker.containsKey(object)) {
				voteTracker.put(object, 1);
			} else {
				Integer currentCount = voteTracker.get(object);
				voteTracker.put(object, new Integer(currentCount + 1));
			}
		}

		// Determine which view is the most consistent
		Object mostCommonConfig = null;
		int maxConsistencies = 0;
		for (Entry<Object, Integer> entry : voteTracker.entrySet()) {
			if (entry.getValue() > maxConsistencies) {
				maxConsistencies = entry.getValue();
				mostCommonConfig = entry.getKey();
			}
		}

		// Ensure there is at least a threshold agreement
		if (maxConsistencies < threshold) {
			throw new BelowThresholdException("Insufficient consistency to permit recovery (below threshold)");
		}

		return mostCommonConfig;
	}

	public abstract class PartialResultTask implements Runnable {

		// Remote server info
		private final int remoteServerId;
		private final String requestUrl;

		// State management
		private final CountDownLatch latch;
		private final AtomicInteger failureCounter;
		private final int maximumFailures;

		public PartialResultTask(final int remoteServerId, final String requestUrl, final List<Object> verifiedResults,
				final CountDownLatch latch, final AtomicInteger failureCounter, final int maximumFailures) {

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
				configureHttps(httpsConnection, remoteServerId);

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
					final Integer serverId = EciesEncryptionClient.this.serverKeys.getEntityIndex(peerPublicKey);
					if (serverId != remoteServerId) {
						System.err.println("Invalid server!!!: was " + serverId + ", expected: " + remoteServerId);
						throw new CertificateException("Invalid peer certificate");
					}

					final String inputLine = bufferedReader.readLine();
					// System.out.println("Received encrypted partial: " + inputLine);

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
				System.err.println(e.getMessage());
			}
		}

		abstract void parseJsonResult(String json) throws Exception;
	}

	private void configureHttps(final HttpsURLConnection httpsConnection, final int remoteServerId)
			throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException,
			UnrecoverableKeyException, KeyManagementException {

		// Configure SSL context
		final SSLContext sslContext = SSLContext.getInstance(HttpRequestProcessor.TLS_VERSION);

		// Create in-memory key store
		final KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
		final char[] password = "password".toCharArray();
		keyStore.load(null, password);

		// Add the CA certificate for the server
		keyStore.setCertificateEntry("ca-" + remoteServerId, this.caCertificates.get(remoteServerId - 1));

		// Add certificate and private key for the server
		// Note: Client CA cert is last after all the servers
		final X509Certificate ourCaCert = this.caCertificates.get(this.serverConfiguration.getNumServers());
		keyStore.setKeyEntry("host", this.clientTlsKey, password,
				new X509Certificate[] { clientCertificate, ourCaCert });

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
