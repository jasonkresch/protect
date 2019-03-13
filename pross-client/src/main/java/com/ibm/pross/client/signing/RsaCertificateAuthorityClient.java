package com.ibm.pross.client.signing;

import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
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

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.DigestInfo;
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
import com.ibm.pross.common.util.certificates.CertificateGeneration;
import com.ibm.pross.common.util.crypto.rsa.threshold.sign.client.RsaSharing;
import com.ibm.pross.common.util.crypto.rsa.threshold.sign.data.SignatureResponse;
import com.ibm.pross.common.util.crypto.rsa.threshold.sign.data.SignatureShareProof;
import com.ibm.pross.common.util.crypto.rsa.threshold.sign.exceptions.BadArgumentException;
import com.ibm.pross.common.util.crypto.rsa.threshold.sign.exceptions.BelowThresholdException;
import com.ibm.pross.common.util.crypto.rsa.threshold.sign.math.ThresholdSignatures;
import com.ibm.pross.common.util.crypto.rsa.threshold.sign.server.ServerPublicConfiguration;
import com.ibm.pross.common.util.serialization.Pem;

import net.i2p.crypto.eddsa.EdDSASecurityProvider;
import sun.security.x509.X509CertImpl;
import sun.security.x509.X509CertInfo;

/**
 * Performs generation and storage of a locally generated RSA private key and
 * can then be used to issue certificates using that distributed private key as
 * the CA's private key
 */
@SuppressWarnings("restriction")
public class RsaCertificateAuthorityClient extends BaseClient {

	public static final String HASH_ALGORITHM = "SHA-512";
	public static final String CERTIFICATE_SIGNING_ALGORITHM = "SHA512withRSA"; // Must match hash algorithm

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

	// Parameters of operation
	private final String secretName;
	private final File caFile;

	// Unique parameters for generating
	private final String issuerDn;

	// Unique parameters for issuing
	private final File publicKeyFile;
	private final File certificateOutputFile;
	private final String subjectDn;

	/**
	 * Constructor for generating a new CA key
	 */
	public RsaCertificateAuthorityClient(final ServerConfiguration serverConfiguration,
			final List<X509Certificate> caCertificates, final KeyLoader serverKeys,
			final X509Certificate clientCertificate, final PrivateKey clientTlsKey, final String secretName,
			final File caFile, final String issuerDn) {

		super(serverConfiguration, caCertificates, serverKeys, clientCertificate, clientTlsKey);

		// USed to generate
		this.secretName = secretName;
		this.caFile = caFile;
		this.issuerDn = issuerDn;

		// Not used
		this.publicKeyFile = null;
		this.certificateOutputFile = null;
		this.subjectDn = null;
	}

	/**
	 * Constructor for issuing a certificate
	 */
	public RsaCertificateAuthorityClient(final ServerConfiguration serverConfiguration,
			final List<X509Certificate> caCertificates, final KeyLoader serverKeys,
			final X509Certificate clientCertificate, final PrivateKey clientTlsKey, final String secretName,
			final File caFile, final File publicKeyFile, final File certificateOutputFile, final String subjectDn) {

		super(serverConfiguration, caCertificates, serverKeys, clientCertificate, clientTlsKey);

		// Used to issue
		this.secretName = secretName;
		this.caFile = caFile;
		this.publicKeyFile = publicKeyFile;
		this.certificateOutputFile = certificateOutputFile;
		this.subjectDn = subjectDn;

		// Not used
		this.issuerDn = null;
	}

	public void generateCaCertificate() throws BadPaddingException, IllegalBlockSizeException, ClassNotFoundException,
			IOException, ResourceUnavailableException, BelowThresholdException, InvalidKeySpecException,
			NoSuchAlgorithmException, CertificateEncodingException {

		// Generates new key
		// Thresholdizes it
		// Stores it
		// Creates a self-signed certificate file at the specified location
		// (Invoke the CA class?)
		// Complete. Storage of RSA to threshold servers. Note this key type does not
		// support proactive refresh nor share recovery! Only use this key for
		// authentication, not for decryption of long term data.

		// Get n and t
		final int numServers = serverConfiguration.getNumServers();
		final int threshold = serverConfiguration.getReconstructionThreshold();

		// Print status of key pair generation
		System.out.println("-----------------------------------------------------------");
		System.out.println("Beginning generation of threshold RSA key...");
		final RsaSharing rsaSharing = RsaSharing.generateSharing(numServers, threshold);
		System.out.println("RSA Key Generation complete.");
		System.out.println();

		// Create and persist CA certificate
		System.out.println("Creating self-signed root CA certificate for: " + issuerDn);
		final X509Certificate caCert = CertificateGeneration.generateCaCertificate(issuerDn, rsaSharing.getKeyPair());
		Pem.storeCertificateToFile(caCert, caFile);
		System.out.println("Certificate written to: " + caFile.getAbsolutePath());
		System.out.println();

		// Store shares and parameters to the shareholders (creating a new sharing state
		// for the server, bump epoch?)
		System.out.print("Storing shares of RSA private key to secret: " + this.secretName + "... ");
		final Boolean success = this.storeRsaSharing(rsaSharing);
		if (success) {
			System.out.println("Storage complete");
		} else {
			System.out.println("Storage failed");
		}
		System.out.println(" (done)");

		System.out.println("CA Creation Completed. Ready to issue certificates.");
		System.out.println(
				"WARNING: Refresh and reconstruction are not active for RSA keys, do not use them for encrypting anything that must be recovered");
	}

	public void issuerCertificate() throws BadPaddingException, IllegalBlockSizeException, ClassNotFoundException,
			IOException, ResourceUnavailableException, BelowThresholdException, NoSuchAlgorithmException,
			CertificateException, InvalidKeySpecException, InvalidKeyException, NoSuchProviderException,
			SignatureException, BadArgumentException {

		// Test most common configuration

		// Use openSSL to verify it

		// Print status
		System.out.println("-----------------------------------------------------------");
		System.out.println("Issing certificate using threshold RSA secret: " + this.secretName);
		System.out.print("  Reading end-entity public key from file: " + this.publicKeyFile + "... ");
		final PublicKey entityPublicKey = (PublicKey) Pem.loadKeyFromFile(this.publicKeyFile);
		System.out.println("done.");

		System.out.print("  Loading CA certificate from file: " + this.publicKeyFile + "... ");
		final X509Certificate caCertificate = Pem.loadCertificateFromFile(caFile);
		System.out.println("done.");

		System.out.print("  Creating a To-Be-Signed Certificate for: " + this.subjectDn + "... ");
		final X509CertInfo certificateInfo = CertificateGeneration.createCertificateInfo(subjectDn, null, null,
				entityPublicKey, 365, false, caCertificate.getSubjectDN().getName(), CERTIFICATE_SIGNING_ALGORITHM);
		final X509CertImpl certificate = new X509CertImpl(certificateInfo);
		final byte[] toBeSigned = certificate.getTBSCertificate();
		final BigInteger toBeSignedRaw = EMSA_PKCS1_V1_5_ENCODE(toBeSigned,
				((RSAPublicKey) caCertificate.getPublicKey()).getModulus());
		System.out.println("done.");

		// Get public key and current epoch from the server
		System.out.print("  Performing threshold signing of certificate using: " + this.secretName + "... ");
		final BigInteger signatureResult = this.signMessage(toBeSignedRaw);
		System.out.println("done.");
		System.out.println("Signature result obtained: " + signatureResult);
		System.out.println();

		System.out.print("  Creating certificate using signature... ");
		final byte[] signature = signatureResult.toByteArray();
		final X509Certificate cert = CertificateGeneration.createCertificateFromTbsAndSignature(certificateInfo,
				CERTIFICATE_SIGNING_ALGORITHM, signature);
		cert.verify(caCertificate.getPublicKey());
		System.out.println("  done. Certificate is valid!");

		// Write plaintext to output file
		System.out.print("Writing signed certificate to file: " + this.certificateOutputFile + "... ");
		Pem.storeCertificateToFile(cert, this.certificateOutputFile);
		System.out.println(" done.");
		System.out.println();

		System.out.println("Operation complete. Certificate now ready for use.");
	}

	public static void main(final String args[]) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException,
			CertificateException, BadPaddingException, IllegalBlockSizeException, ClassNotFoundException,
			ResourceUnavailableException, BelowThresholdException, InvalidKeyException, NoSuchProviderException,
			SignatureException, BadArgumentException {

		// Parse arguments
		if (args.length < 6) {
			System.err.println(
					"USAGE: config-dir username secretname [GENERATE] ca-certificate-output-file \"Issuer DN\"");
			System.err.println(
					"USAGE: config-dir username secretname [ISSUE] ca-certificate-input-file public-key-input-file issued-certificate-output-file \"Subject DN\"");
			System.exit(-1);
		}
		final File baseDirectory = new File(args[0]);
		final String username = args[1];
		final String secretName = args[2];
		final boolean generate = "GENERATE".equalsIgnoreCase(args[3]);
		final File caFile = new File(args[4]);

		String issuerDn = null;
		File publicKeyFile = null;
		File certificateOutputFile = null;
		String subjectDn = null;
		if (!generate) {
			if (!caFile.exists()) {
				System.err.println("CA file does not exist: " + caFile.getAbsolutePath());
				System.exit(-1);
			}

			// Issue certificate
			if (args.length < 8) {
				System.err.println(
						"USAGE: config-dir username secretname [ISSUE] ca-certificate-input-file public-key-input-file issued-certificate-output-file \"Subject DN\"");
				System.exit(-1);
			}
			publicKeyFile = new File(args[5]);

			if (!publicKeyFile.exists()) {
				System.err.println("PublicKey file does not exist: " + publicKeyFile.getAbsolutePath());
				System.exit(-1);
			}

			certificateOutputFile = new File(args[6]);
			subjectDn = args[7];
		} else {
			// Generate certificate and store key
			issuerDn = args[5];
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

		// Perform operation
		if (generate) {
			// Create new generation client
			final RsaCertificateAuthorityClient signingClient = new RsaCertificateAuthorityClient(configuration,
					caCerts, serverKeys, clientCertificate, clientPrivateKey, secretName, caFile, issuerDn);
			signingClient.generateCaCertificate();
		} else {
			// Create new issuing client
			final RsaCertificateAuthorityClient signingClient = new RsaCertificateAuthorityClient(configuration,
					caCerts, serverKeys, clientCertificate, clientPrivateKey, secretName, caFile, publicKeyFile,
					certificateOutputFile, subjectDn);
			signingClient.issuerCertificate();
		}
	}

	private static SignatureResponse createSignatureResult(Object obj) {
		return (SignatureResponse) obj;
	}

	/**
	 * Interacts with the servers to store an RSA sharing to a given secret
	 * 
	 * @param rsaSharing
	 * @return
	 * @throws ResourceUnavailableException
	 * @throws BelowThresholdException
	 */
	private Boolean storeRsaSharing(final RsaSharing rsaSharing)
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
		final List<Object> successfulResults = Collections.synchronizedList(new ArrayList<>());

		// Collect pulic data to register with servers

		// Send the public exponenet to the server
		final BigInteger exponent = rsaSharing.getPublicKey().getPublicExponent();

		// Send the modulus to the server
		final BigInteger modulus = rsaSharing.getPublicKey().getModulus();

		// Send the generator to the server
		final BigInteger v = rsaSharing.getV();

		StringBuilder allVerificationKeys = new StringBuilder();
		for (int i = 1; i <= this.serverConfiguration.getNumServers(); i++) {
			allVerificationKeys.append("&v_" + i + "=" + rsaSharing.getVerificationKeys()[i - 1]);
		}

		// Create a partial result task for everyone except ourselves
		int serverId = 0;
		for (final InetSocketAddress serverAddress : this.serverConfiguration.getServerAddresses()) {
			serverId++;
			final String serverIp = serverAddress.getAddress().getHostAddress();
			final int serverPort = CommonConfiguration.BASE_HTTP_PORT + serverId;

			// Send share to the server
			final BigInteger share = rsaSharing.getShares()[serverId - 1].getY();

			final String linkUrl = "https://" + serverIp + ":" + serverPort + "/store?secretName=" + this.secretName
					+ "&e=" + exponent + "&n=" + modulus + "&v=" + v + allVerificationKeys.toString() + "&share="
					+ share;

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
	 * Interacts with the servers to sign a message using the given secret
	 * 
	 * @param inputPoint
	 * @return
	 * @throws ResourceUnavailableException
	 * @throws BadArgumentException
	 * @throws BelowThresholdException
	 */
	private BigInteger signMessage(final BigInteger toBeSigned)
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
		final List<Object> signatureResponses = Collections.synchronizedList(new ArrayList<>());
		final List<Object> publicConfigurations = Collections.synchronizedList(new ArrayList<>());

		// Create a partial result task for everyone except ourselves
		int serverId = 0;
		for (final InetSocketAddress serverAddress : this.serverConfiguration.getServerAddresses()) {
			serverId++;
			final String serverIp = serverAddress.getAddress().getHostAddress();
			final int serverPort = CommonConfiguration.BASE_HTTP_PORT + serverId;
			final String linkUrl = "https://" + serverIp + ":" + serverPort + "/sign?secretName=" + this.secretName
					+ "&message=" + toBeSigned.toString();

			final int thisServerId = serverId;

			// Create new task to get the partial exponentiation result from the server
			executor.submit(new PartialResultTask(this, serverId, linkUrl, signatureResponses, latch, failureCounter,
					maximumFailures) {
				@Override
				protected void parseJsonResult(final String json) throws Exception {

					// FIXME: Do majority voting of correct parameters

					// Parse JSON
					final JSONParser parser = new JSONParser();
					final Object obj = parser.parse(json);
					final JSONObject jsonObject = (JSONObject) obj;
					final Long responder = (Long) jsonObject.get("responder");
					final long epoch = (Long) jsonObject.get("epoch");
					final BigInteger signatureShare = new BigInteger((String) jsonObject.get("share"));

					final JSONArray proof = (JSONArray) jsonObject.get("share_proof");
					final BigInteger c = new BigInteger((String) proof.get(0));
					final BigInteger z = new BigInteger((String) proof.get(1));

					final BigInteger e = new BigInteger((String) jsonObject.get("e"));
					final BigInteger n = new BigInteger((String) jsonObject.get("n"));
					final BigInteger v = new BigInteger((String) jsonObject.get("v"));

					final BigInteger[] sharePublicKeys = new BigInteger[numShareholders];
					final JSONArray vertificationKeys = (JSONArray) jsonObject.get("verification_keys");
					for (int i = 0; i < numShareholders; i++) {
						sharePublicKeys[i] = new BigInteger((String) vertificationKeys.get(i));
					}

					// Verify result
					// TOOD: Implement retry if epoch mismatch and below threshold
					if ((responder == thisServerId)) {

						// Add both to lists, one is private, one is public and should be agreed upon
						final SignatureResponse signatureResponse = new SignatureResponse(
								BigInteger.valueOf(thisServerId), signatureShare, new SignatureShareProof(c, z));
						final ServerPublicConfiguration publicConfiguration = new ServerPublicConfiguration(
								numShareholders, reconstructionThreshold, n, e, v, sharePublicKeys);

						// Store result for later processing
						signatureResponses.add(signatureResponse);
						publicConfigurations.add(publicConfiguration);

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

			// Get consistent view of public sharings
			final ServerPublicConfiguration publicConfiguration = (ServerPublicConfiguration) getConsistentConfiguration(
					publicConfigurations, reconstructionThreshold);

			// Check that we have enough results to interpolate the share
			if (failureCounter.get() <= maximumFailures) {

				final List<SignatureResponse> results = signatureResponses.stream()
						.map(obj -> createSignatureResult(obj)).collect(Collectors.toList());

				// When complete, interpolate the result at zero (where the secret lies)
				final BigInteger signature = ThresholdSignatures.recoverSignature(toBeSigned, results,
						publicConfiguration);

				executor.shutdown();

				return signature;
			} else {
				executor.shutdown();
				throw new ResourceUnavailableException();
			}
		} catch (InterruptedException e) {
			throw new RuntimeException(e);
		}
	}

	/*** Static Methods ***/

	private static BigInteger EMSA_PKCS1_V1_5_ENCODE(byte[] input, final BigInteger modulus)
			throws NoSuchAlgorithmException, IOException {

		// Digest the input
		final MessageDigest md = MessageDigest.getInstance(HASH_ALGORITHM);
		final byte[] digest = md.digest(input);

		// Create a digest info consisting of the algorithm id and the hash
		final AlgorithmIdentifier algId = new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha512, DERNull.INSTANCE);
		final DigestInfo digestInfo = new DigestInfo(algId, digest);
		final byte[] message = digestInfo.getEncoded(ASN1Encoding.DER);

		// Do PKCS1 padding
		final byte[] block = new byte[((modulus.bitLength() + 7) / 8) - 1];
		System.arraycopy(message, 0, block, block.length - message.length, message.length);
		block[0] = 0x01; // type code 1
		for (int i = 1; i != block.length - message.length - 1; i++) {
			block[i] = (byte) 0xFF;
		}

		return new BigInteger(1, block);
	}

}
