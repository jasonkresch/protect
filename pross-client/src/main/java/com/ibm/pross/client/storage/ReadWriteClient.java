package com.ibm.pross.client.storage;

import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.AbstractMap.SimpleEntry;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Collectors;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;

import com.ibm.pross.client.util.BaseClient;
import com.ibm.pross.client.util.PartialResultTask;
import com.ibm.pross.common.config.CommonConfiguration;
import com.ibm.pross.common.config.KeyLoader;
import com.ibm.pross.common.config.ServerConfiguration;
import com.ibm.pross.common.config.ServerConfigurationLoader;
import com.ibm.pross.common.exceptions.http.ResourceUnavailableException;
import com.ibm.pross.common.util.crypto.ecc.EcPoint;
import com.ibm.pross.common.util.crypto.rsa.threshold.sign.exceptions.BadArgumentException;
import com.ibm.pross.common.util.crypto.rsa.threshold.sign.exceptions.BelowThresholdException;
import com.ibm.pross.common.util.serialization.Pem;
import com.ibm.pross.common.util.shamir.Polynomials;
import com.ibm.pross.common.util.shamir.Shamir;
import com.ibm.pross.common.util.shamir.ShamirShare;

import net.i2p.crypto.eddsa.EdDSASecurityProvider;

/**
 * Performs storage of an arbitrary secret value, and then can read back shares
 * of that secret to recover the secret
 */
@SuppressWarnings("restriction")
public class ReadWriteClient extends BaseClient {

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

	// Parameters of the operation
	private final String secretName;
	private final BigInteger secretToStore;

	/**
	 * Constructor for storing a new secret
	 */
	public ReadWriteClient(final ServerConfiguration serverConfiguration, final List<X509Certificate> caCertificates,
			final KeyLoader serverKeys, final X509Certificate clientCertificate, final PrivateKey clientTlsKey,
			final String secretName, final BigInteger secretToStore) {
		
		super(serverConfiguration, caCertificates, serverKeys, clientCertificate, clientTlsKey);
		
		// Used to write secret
		this.secretName = secretName;
		this.secretToStore = secretToStore;
	}

	/**
	 * Constructor for issuing a certificate
	 */
	public ReadWriteClient(final ServerConfiguration serverConfiguration, final List<X509Certificate> caCertificates,
			final KeyLoader serverKeys, final X509Certificate clientCertificate, final PrivateKey clientTlsKey,
			final String secretName) {
		
		super(serverConfiguration, caCertificates, serverKeys, clientCertificate, clientTlsKey);
		
		// Used to read secret
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
		final Boolean dkgSuccess = this.storeShares();
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
			final int serverPort = CommonConfiguration.BASE_HTTP_PORT + serverId;

			// Send share to the server
			final BigInteger share = shares[serverId - 1].getY();

			final String linkUrl = "https://" + serverIp + ":" + serverPort + "/store?secretName=" + this.secretName
					+ "&share=" + share;

			// Create new task to get the partial exponentiation result from the server
			executor.submit(new PartialResultTask(this, serverId, linkUrl, successfulResults, latch, failureCounter,
					maximumFailures) {
				@Override
				protected void parseJsonResult(final String json) throws Exception {
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
	private Boolean storeShares() throws ResourceUnavailableException, BelowThresholdException {

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
			final int serverPort = CommonConfiguration.BASE_HTTP_PORT + serverId;

			final String linkUrl = "https://" + serverIp + ":" + serverPort + "/generate?secretName=" + this.secretName;

			// Create new task to get the partial exponentiation result from the server
			executor.submit(new PartialResultTask(this, serverId, linkUrl, successfulResults, latch, failureCounter,
					maximumFailures) {
				@Override
				protected void parseJsonResult(final String json) throws Exception {
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

		// Create a partial result task for everyone except ourselves
		int serverId = 0;
		for (final InetSocketAddress serverAddress : this.serverConfiguration.getServerAddresses()) {
			serverId++;
			final String serverIp = serverAddress.getAddress().getHostAddress();
			final int serverPort = CommonConfiguration.BASE_HTTP_PORT + serverId;
			final String linkUrl = "https://" + serverIp + ":" + serverPort + "/read?secretName=" + this.secretName
					+ "&json=true";

			final int thisServerId = serverId;

			// Create new task to get the partial exponentiation result from the server
			executor.submit(new PartialResultTask(this, serverId, linkUrl, shareResponses, latch, failureCounter,
					maximumFailures) {
				@Override
				protected void parseJsonResult(final String json) throws Exception {

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


}
