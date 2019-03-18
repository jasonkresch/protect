package com.ibm.pross.client.encryption;

import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.nio.file.Files;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
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

import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;

import com.ibm.pross.client.util.BaseClient;
import com.ibm.pross.client.util.PartialResultTask;
import com.ibm.pross.common.DerivationResult;
import com.ibm.pross.common.config.CommonConfiguration;
import com.ibm.pross.common.config.KeyLoader;
import com.ibm.pross.common.config.ServerConfiguration;
import com.ibm.pross.common.config.ServerConfigurationLoader;
import com.ibm.pross.common.exceptions.http.ResourceUnavailableException;
import com.ibm.pross.common.util.crypto.ecc.EcPoint;
import com.ibm.pross.common.util.crypto.elgamal.EciesEncryption;
import com.ibm.pross.common.util.crypto.rsa.threshold.sign.exceptions.BelowThresholdException;
import com.ibm.pross.common.util.serialization.Pem;
import com.ibm.pross.common.util.shamir.Polynomials;

/**
 * Performs ECIES (Elliptic Curve based ElGamal Encryption and Decryption of
 * files used a distributed secret key)
 */
public class EciesEncryptionClient extends BaseClient {

	// Parameters of operation
	private final String secretName;
	private final File inputFile;
	private final File outputFile;

	public EciesEncryptionClient(final ServerConfiguration serverConfiguration,
			final List<X509Certificate> caCertificates, final KeyLoader serverKeys,
			final X509Certificate clientCertificate, PrivateKey clientTlsKey, final String secretName,
			final File inputFile, final File outputFile) {

		super(serverConfiguration, caCertificates, serverKeys, clientCertificate, clientTlsKey);

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
		final SimpleEntry<List<EcPoint>, Long> shareVerificationKeysAndEpoch = this.getServerVerificationKeys(secretName);
		System.out.println(" (done)");
		final EcPoint publicKey = shareVerificationKeysAndEpoch.getKey().get(0);
		final long currentEpoch = shareVerificationKeysAndEpoch.getValue();
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
		final SimpleEntry<List<EcPoint>, Long> shareVerificationKeysAndEpoch = this.getServerVerificationKeys(secretName);
		System.out.println(" (done)");
		final EcPoint publicKey = shareVerificationKeysAndEpoch.getKey().get(0);
		final long currentEpoch = shareVerificationKeysAndEpoch.getValue();
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
				clientCertificate, clientPrivateKey, secretName, inputFile, outputFile);

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
			final int serverPort = CommonConfiguration.BASE_HTTP_PORT + serverId;
			final String linkUrl = "https://" + serverIp + ":" + serverPort + "/exponentiate?secretName="
					+ this.secretName + "&x=" + inputPoint.getX() + "&y=" + inputPoint.getY() + "&json=true";

			final int thisServerId = serverId;

			// Create new task to get the partial exponentiation result from the server
			executor.submit(new PartialResultTask(this, serverId, linkUrl, verifiedResults, latch, failureCounter,
					maximumFailures) {
				@Override
				protected void parseJsonResult(final String json) throws Exception {

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
						throw new Exception(
								"Server " + thisServerId + " sent inconsistent results (likely during epoch change)");
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

}
