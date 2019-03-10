package com.ibm.pross.client;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.net.URL;
import java.security.InvalidKeyException;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
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
import com.ibm.pross.common.util.crypto.ecc.EcPoint;
import com.ibm.pross.common.util.crypto.rsa.threshold.sign.data.SignatureResponse;
import com.ibm.pross.common.util.crypto.rsa.threshold.sign.data.SignatureShareProof;
import com.ibm.pross.common.util.crypto.rsa.threshold.sign.exceptions.BadArgumentException;
import com.ibm.pross.common.util.crypto.rsa.threshold.sign.exceptions.BelowThresholdException;
import com.ibm.pross.common.util.crypto.rsa.threshold.sign.math.ThresholdSignatures;
import com.ibm.pross.common.util.crypto.rsa.threshold.sign.server.ServerPublicConfiguration;
import com.ibm.pross.common.util.serialization.Pem;
import com.ibm.pross.common.util.shamir.Polynomials;
import com.ibm.pross.common.util.shamir.Shamir;
import com.ibm.pross.common.util.shamir.ShamirShare;
import com.ibm.pross.server.app.http.HttpRequestProcessor;
import com.ibm.pross.server.configuration.permissions.exceptions.ResourceUnavailableException;

import bftsmart.reconfiguration.util.sharedconfig.KeyLoader;
import bftsmart.reconfiguration.util.sharedconfig.ServerConfiguration;
import bftsmart.reconfiguration.util.sharedconfig.ServerConfigurationLoader;
import net.i2p.crypto.eddsa.EdDSASecurityProvider;

/**
 * Performs storage of an arbitrary secret value, and then can read back shares
 * of that secret to recover the secret
 */
@SuppressWarnings("restriction")
public class ReadWriteClient {

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

	// Parameters of the operation
	private final String secretName;
	private final BigInteger secretToStore;

	/**
	 * Constructor for storing a new secret
	 */
	public ReadWriteClient(final ServerConfiguration serverConfiguration, final List<X509Certificate> caCertificates,
			final KeyLoader serverKeys, final X509Certificate clientCertificate, final PrivateKey clientTlsKey,
			final String secretName, final BigInteger secretToStore) {
		this.serverConfiguration = serverConfiguration;
		this.caCertificates = caCertificates;
		this.serverKeys = serverKeys;
		this.clientCertificate = clientCertificate;
		this.clientTlsKey = clientTlsKey;
		this.secretName = secretName;
		this.secretToStore = secretToStore;
	}

	/**
	 * Constructor for issuing a certificate
	 */
	public ReadWriteClient(final ServerConfiguration serverConfiguration, final List<X509Certificate> caCertificates,
			final KeyLoader serverKeys, final X509Certificate clientCertificate, final PrivateKey clientTlsKey,
			final String secretName) {
		this.serverConfiguration = serverConfiguration;
		this.caCertificates = caCertificates;
		this.serverKeys = serverKeys;
		this.clientCertificate = clientCertificate;
		this.clientTlsKey = clientTlsKey;
		this.secretName = secretName;

		// Not used
		this.secretToStore = null;
	}

	public void writeSecret() throws BadPaddingException, IllegalBlockSizeException, ClassNotFoundException,
			IOException, ResourceUnavailableException, BelowThresholdException, InvalidKeySpecException,
			NoSuchAlgorithmException, CertificateEncodingException, InterruptedException {

		// Thresholdizes the given secret
		// Stores each share to shareholder
		// Initiates a dkg using that secret
		// Outputs the public key of the secret to verify stored correctly

		// Get n and t
		final int numServers = serverConfiguration.getNumServers();
		final int threshold = serverConfiguration.getReconstructionThreshold();

		// Print status of key pair generation
		System.out.println("-----------------------------------------------------------");
		System.out.println("Generating shares of the provided secret...");
		final EcPoint publicKeyOfSecret = CommonConfiguration.CURVE.multiply(CommonConfiguration.g, secretToStore);
		System.out.println("Public key of secret = " + publicKeyOfSecret);
		final BigInteger[] coefficients = Shamir.generateCoefficients(threshold);
		coefficients[0] = secretToStore;
		final ShamirShare[] shares = Shamir.generateShares(coefficients, numServers);
		System.out.println("Generation of shares complete.");
		System.out.println();

		// Store shares and parameters to the shareholders
		System.out.print("Storing shares to secret: " + this.secretName + "... ");
		final Boolean storageSuccess = this.storeSecret(shares);
		if (!storageSuccess) {
			System.err.println("\nStorage failed");
			System.exit(-1);
		}
		System.out.println(" (done)");

		// Initiating DKG
		System.out.print("Initiating DKG for secret: " + this.secretName + "... ");
		final Boolean dkgSuccess = this.performDkg();
		if (!dkgSuccess) {
			System.out.println("DKG failed, secret is not available");
		}
		System.out.println(" (done)");

		// Initiating DKG
		Thread.sleep(5000);
		System.out.println(" (done)");
		
		// Verify DKG
		// Get public keys from the server
		System.out.print("Accessing public key for secret: " + this.secretName + "... ");
		final SimpleEntry<List<EcPoint>, Long> publicKeyAndEpoch = this.getServerVerificationKeys(secretName);
		System.out.println(" (done)");
		final List<EcPoint> publicKeys = publicKeyAndEpoch.getKey();
		System.out.println("Stored Public key for secret:    " + publicKeys.get(0));
		boolean secretsMatch = publicKeyOfSecret.equals(publicKeys.get(0));
		System.out.println();

		if (secretsMatch) {
			System.out.println("DKG complete. Secret is now stored and available for reading.");
		} else {
			System.err.println("DKG complete but stored result does not match what we attempted to store.");
			System.exit(-1);
		}

	}

	public void readSecret() throws BadPaddingException, IllegalBlockSizeException, ClassNotFoundException, IOException,
			ResourceUnavailableException, BelowThresholdException, NoSuchAlgorithmException, CertificateException,
			InvalidKeySpecException, InvalidKeyException, NoSuchProviderException, SignatureException,
			BadArgumentException {

		// Perform read to all servers
		// Validate each result before adding it to the list
		// On read, print the restored secret's public key
		// Compare to the public key that was return getting the info of the secret
		// TODO: Compare returned shares against (most common feldman commitments
		// Print the secret to standard out

		// Print status
		System.out.println("-----------------------------------------------------------");

		// Get public keys from the server
		System.out.print("Accessing public key for secret: " + this.secretName + "... ");
		final SimpleEntry<List<EcPoint>, Long> publicKeyAndEpoch = this.getServerVerificationKeys(secretName);
		System.out.println(" (done)");
		final List<EcPoint> publicKeys = publicKeyAndEpoch.getKey();
		System.out.println("Stored Public key for secret:    " + publicKeys.get(0));
		System.out.println();

		// Attempt recovery of the stored secret
		System.out.println("Reading shares to decode secret: " + this.secretName);
		final BigInteger recoveredSecret = this.readShares(publicKeys);
		final EcPoint publicKeyOfSecret = CommonConfiguration.CURVE.multiply(CommonConfiguration.g, recoveredSecret);
		System.out.println("Public key of recvered secret = " + publicKeyOfSecret);
		boolean secretsMatch = publicKeyOfSecret.equals(publicKeys.get(0));
		System.out.println("done.");
		System.out.println();

		if (secretsMatch) {
			System.out.println("Value of secret: " + recoveredSecret);
		} else {
			System.err.println("Failed to recover secret");
			System.exit(-1);
		}
	}

	public static void main(final String args[]) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException,
			CertificateException, BadPaddingException, IllegalBlockSizeException, ClassNotFoundException,
			ResourceUnavailableException, BelowThresholdException, InvalidKeyException, NoSuchProviderException,
			SignatureException, BadArgumentException, InterruptedException {

		// Parse arguments
		if (args.length < 4) {
			System.err.println("USAGE: config-dir username secretname [WRITE] secret-value");
			System.err.println("USAGE: config-dir username secretname [READ]");
			System.exit(-1);
		}
		final File baseDirectory = new File(args[0]);
		final String username = args[1];
		final String secretName = args[2];
		final boolean write = "WRITE".equalsIgnoreCase(args[3]);
		final BigInteger secretToStore;

		if (write) {

			// Issue certificate
			if (args.length < 5) {
				System.err.println("USAGE: config-dir username secretname [WRITE] secret-value");
				System.exit(-1);
			}
			secretToStore = new BigInteger(args[4]);

			// Check range
			if (secretToStore.compareTo(BigInteger.ONE) < 0) {
				System.err.println("Secret to store must be greater than zero");
				System.exit(-1);
			}

			if (secretToStore.compareTo(CommonConfiguration.CURVE.getR()) >= 0) {
				System.err.println("Secret to store must be less than " + CommonConfiguration.CURVE.getR());
				System.exit(-1);
			}
		} else {
			secretToStore = null;
		}

		// Load server configuration (learn n and k)
		final File configFile = new File(baseDirectory, CONFIG_FILENAME);
		final ServerConfiguration configuration = ServerConfigurationLoader.load(configFile);
		System.out.println(configuration);

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

		// Perform operation
		if (write) {
			// Create writing client
			final ReadWriteClient storageClient = new ReadWriteClient(configuration, caCerts, serverKeys,
					clientCertificate, clientPrivateKey, secretName, secretToStore);
			storageClient.writeSecret();
		} else {
			// Create reading client
			final ReadWriteClient signingClient = new ReadWriteClient(configuration, caCerts, serverKeys,
					clientCertificate, clientPrivateKey, secretName);
			signingClient.readSecret();
		}
	}

	private static ShamirShare createShamirShare(Object obj) {
		return (ShamirShare) obj;
	}

	/**
	 * Interacts with the servers to store an shares of a user provided secret
	 * 
	 * @param shares
	 * @return
	 * @throws ResourceUnavailableException
	 * @throws BelowThresholdException
	 */
	private Boolean storeSecret(final ShamirShare[] shares)
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

		// Each task deposits its result into this map after verifying it is good
		final List<Object> successfulResults = Collections.synchronizedList(new ArrayList<>());

		// Create a partial result task for everyone
		int serverId = 0;
		for (final InetSocketAddress serverAddress : this.serverConfiguration.getServerAddresses()) {
			serverId++;
			final String serverIp = serverAddress.getAddress().getHostAddress();
			final int serverPort = HttpRequestProcessor.BASE_HTTP_PORT + serverId;

			// Send share to the server
			final BigInteger share = shares[serverId - 1].getY();

			final String linkUrl = "https://" + serverIp + ":" + serverPort + "/store?secretName=" + this.secretName
					+ "&share=" + share;

			// Create new task to get the partial exponentiation result from the server
			executor.submit(new PartialResultTask(serverId, linkUrl, successfulResults, latch, failureCounter,
					maximumFailures) {
				@Override
				void parseJsonResult(final String json) throws Exception {
					// Store result for later processing
					successfulResults.add(Boolean.TRUE);

					// Everything checked out, increment successes
					latch.countDown();
				}
			});
		}

		try {
			// Once we have K successful responses we can interpolate our share
			latch.await();

			// Check that we have enough results to interpolate the share
			if (failureCounter.get() <= maximumFailures) {

				// When complete, interpolate the result at zero (where the secret lies)
				final Boolean wereSuccessful = (Boolean) getConsistentConfiguration(successfulResults,
						reconstructionThreshold);
				executor.shutdown();

				return wereSuccessful;
			} else {
				executor.shutdown();
				throw new ResourceUnavailableException();
			}
		} catch (InterruptedException e) {
			throw new RuntimeException(e);
		}
	}

	/**
	 * Tells each of the servers to perform a DKG, we count this as a success if any
	 * server succeeds
	 * 
	 * @return
	 * @throws ResourceUnavailableException
	 * @throws BelowThresholdException
	 */
	private Boolean performDkg() throws ResourceUnavailableException, BelowThresholdException {

		// Server configuration
		final int numShareholders = this.serverConfiguration.getNumServers();

		// We create a thread pool with a thread for each task and remote server
		final ExecutorService executor = Executors.newFixedThreadPool(numShareholders - 1);

		// The countdown latch tracks progress towards reaching a threshold (in this
		// case 1)
		final CountDownLatch latch = new CountDownLatch(1);
		final AtomicInteger failureCounter = new AtomicInteger(0);
		final int maximumFailures = (numShareholders - 1);

		// Each task deposits its result into this map after verifying it is good
		final List<Object> successfulResults = Collections.synchronizedList(new ArrayList<>());

		// Create a partial result task for everyone
		int serverId = 0;
		for (final InetSocketAddress serverAddress : this.serverConfiguration.getServerAddresses()) {
			serverId++;
			final String serverIp = serverAddress.getAddress().getHostAddress();
			final int serverPort = HttpRequestProcessor.BASE_HTTP_PORT + serverId;

			final String linkUrl = "https://" + serverIp + ":" + serverPort + "/generate?secretName=" + this.secretName;

			// Create new task to get the partial exponentiation result from the server
			executor.submit(new PartialResultTask(serverId, linkUrl, successfulResults, latch, failureCounter,
					maximumFailures) {
				@Override
				void parseJsonResult(final String json) throws Exception {
					// Store result for later processing
					successfulResults.add(Boolean.TRUE);

					// Everything checked out, increment successes
					latch.countDown();
				}
			});
		}

		try {
			// Once we have 1 successful response we can interpolate our share
			latch.await();

			// Check that we have enough results to interpolate the share
			if (failureCounter.get() <= maximumFailures) {

				executor.shutdown();

				return true;
			} else {
				executor.shutdown();
				throw new ResourceUnavailableException();
			}
		} catch (InterruptedException e) {
			throw new RuntimeException(e);
		}
	}

	/**
	 * Interacts with the servers to read shares and decode a secret
	 * 
	 * @param publicKeys
	 * 
	 * @param inputPoint
	 * @return
	 * @throws ResourceUnavailableException
	 * @throws BadArgumentException
	 * @throws BelowThresholdException
	 */
	private BigInteger readShares(final List<EcPoint> publicKeys)
			throws ResourceUnavailableException, BadArgumentException, BelowThresholdException {

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
		final List<Object> shareResponses = Collections.synchronizedList(new ArrayList<>());
		final List<Object> publicConfigurations = Collections.synchronizedList(new ArrayList<>());

		// Create a partial result task for everyone except ourselves
		int serverId = 0;
		for (final InetSocketAddress serverAddress : this.serverConfiguration.getServerAddresses()) {
			serverId++;
			final String serverIp = serverAddress.getAddress().getHostAddress();
			final int serverPort = HttpRequestProcessor.BASE_HTTP_PORT + serverId;
			final String linkUrl = "https://" + serverIp + ":" + serverPort + "/read?secretName=" + this.secretName
					+ "&json=true";

			final int thisServerId = serverId;

			// Create new task to get the partial exponentiation result from the server
			executor.submit(new PartialResultTask(serverId, linkUrl, shareResponses, latch, failureCounter,
					maximumFailures) {
				@Override
				void parseJsonResult(final String json) throws Exception {

					// Parse JSON
					final JSONParser parser = new JSONParser();
					final Object obj = parser.parse(json);
					final JSONObject jsonObject = (JSONObject) obj;
					final Long responder = (Long) jsonObject.get("responder");
					final long epoch = (Long) jsonObject.get("epoch");
					if (jsonObject.get("share") != null) {
						final BigInteger share = new BigInteger((String) jsonObject.get("share"));

						// Verify result
						if ((responder == thisServerId)) {

							// Check consistency of share against known public key
							final EcPoint computedPublicKey = CommonConfiguration.CURVE.multiply(CommonConfiguration.g,
									share);
							if (!computedPublicKey.equals(publicKeys.get(thisServerId))) {
								throw new Exception("Server " + thisServerId
										+ " sent a share inconsistent with its known public key");
							}

							// Create a shamir share object and add it to the list of responses
							final ShamirShare shamirShare = new ShamirShare(BigInteger.valueOf(thisServerId), share);

							// Store result for later processing
							shareResponses.add(shamirShare);

							// Everything checked out, increment successes
							latch.countDown();
						} else {
							throw new Exception("Server " + thisServerId
									+ " sent inconsistent results (likely during epoch change)");
						}

					} else {
						// Share was deleted, treat this as a failure
						throw new Exception("Server " + thisServerId + " is missing a share");
					}
				}
			});
		}

		try {
			// Once we have K successful responses we can interpolate our share
			latch.await();

			// Check that we have enough results to interpolate the share
			if (failureCounter.get() <= maximumFailures) {

				final List<ShamirShare> results = shareResponses.stream()
						.map(obj -> createShamirShare(obj)).collect(Collectors.toList());

				// When complete, interpolate the result at zero (where the secret lies)
				final BigInteger secret = Polynomials.interpolateComplete(results, reconstructionThreshold, 0);

				executor.shutdown();

				return secret;
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
	private SimpleEntry<List<EcPoint>, Long> getServerVerificationKeys(final String secretName)
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
							final List<EcPoint> verificationKeys = new ArrayList<>();

							final JSONArray publicKeyPoint = (JSONArray) jsonObject.get("public_key");
							final BigInteger x = new BigInteger((String) publicKeyPoint.get(0));
							final BigInteger y = new BigInteger((String) publicKeyPoint.get(1));
							verificationKeys.add(new EcPoint(x, y));
							for (int i = 1; i <= numShareholders; i++) {
								final JSONArray verificationKey = (JSONArray) jsonObject
										.get("share_verification_key_" + i);
								final BigInteger x2 = new BigInteger((String) verificationKey.get(0));
								final BigInteger y2 = new BigInteger((String) verificationKey.get(1));
								verificationKeys.add(new EcPoint(x2, y2));
							}

							// Store parsed result
							if ((responder == thisServerId)) {

								// Store result for later processing
								collectedResults.add(new SimpleEntry<List<EcPoint>, Long>(verificationKeys, epoch));

								// Everything checked out, increment successes
								latch.countDown();
							} else {
								throw new Exception("Server " + thisServerId + " sent inconsistent results");
							}

						}
					});
		}

		try {
			// Once we have K successful responses we attempt to find a consistent
			// configuration
			// FIXME: There is a better way of doing this, map result to a counter, wait for
			// counter to reach majority (or fail)
			// if not enough remaining responses permit getting a majority
			latch.await();

			// Check that we have enough results to interpolate the share
			if (failureCounter.get() <= maximumFailures) {

				executor.shutdown();

				return (SimpleEntry<List<EcPoint>, Long>) getConsistentConfiguration(collectedResults,
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
				voteTracker.put(object, Integer.valueOf(currentCount + 1));
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
			System.out.println();
			for (Object o : configurationData) {
				System.out.println(" --- " + o);
			}
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
					final Integer serverId = ReadWriteClient.this.serverKeys.getEntityIndex(peerPublicKey);
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
