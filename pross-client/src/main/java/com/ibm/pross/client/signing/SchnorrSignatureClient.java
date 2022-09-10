package com.ibm.pross.client.signing;

import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.AbstractMap.SimpleEntry;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map.Entry;
import java.util.SortedMap;
import java.util.SortedSet;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.UUID;
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
import com.ibm.pross.common.config.CommonConfiguration;
import com.ibm.pross.common.config.KeyLoader;
import com.ibm.pross.common.config.ServerConfiguration;
import com.ibm.pross.common.config.ServerConfigurationLoader;
import com.ibm.pross.common.exceptions.http.ResourceUnavailableException;
import com.ibm.pross.common.util.crypto.ecc.EcCurve;
import com.ibm.pross.common.util.crypto.ecc.EcPoint;
import com.ibm.pross.common.util.crypto.rsa.threshold.sign.exceptions.BelowThresholdException;
import com.ibm.pross.common.util.crypto.schnorr.NonceCommitment;
import com.ibm.pross.common.util.crypto.schnorr.SchnorrSignatures;
import com.ibm.pross.common.util.crypto.schnorr.SchnorrUtil;
import com.ibm.pross.common.util.serialization.HexUtil;
import com.ibm.pross.common.util.serialization.Parse;
import com.ibm.pross.common.util.serialization.Pem;
import com.ibm.pross.common.util.shamir.Polynomials;

/**
 * Performs FROST style ( https://eprint.iacr.org/2020/852.pdf ) distributed
 * Schnorr signature calculation (An Elliptic Curve based signature scheme)
 */
public class SchnorrSignatureClient extends BaseClient {

	// Parameters of operation
	private final String secretName;
	private final File inputFile;
	private final File signatureFile;

	public SchnorrSignatureClient(final ServerConfiguration serverConfiguration,
			final List<X509Certificate> caCertificates, final KeyLoader serverKeys,
			final X509Certificate clientCertificate, PrivateKey clientTlsKey, final String secretName,
			final File inputFile, final File signatureFile) {

		super(serverConfiguration, caCertificates, serverKeys, clientCertificate, clientTlsKey);

		this.secretName = secretName;
		this.inputFile = inputFile;
		this.signatureFile = signatureFile;
	}

	public void signFile() throws BadPaddingException, IllegalBlockSizeException, ClassNotFoundException, IOException,
			ResourceUnavailableException, BelowThresholdException, NoSuchAlgorithmException {

		// Print status
		System.out.println("-----------------------------------------------------------");
		System.out.println("Beginning signature generation for file: " + this.inputFile);

		// Reading input file to sign
		System.out.print("Reading input file: " + this.inputFile + "... ");
		final byte[] messageBytes = Files.readAllBytes(inputFile.toPath());
		System.out.println(" (done)");
		System.out.println("Read " + messageBytes.length + " bytes of input to sign.");
		System.out.println();

		// Get public key and current epoch from the server
		System.out.print("Accessing public key for secret: " + this.secretName + "... ");
		final SimpleEntry<List<EcPoint>, Long> shareVerificationKeysAndEpoch = this
				.getServerVerificationKeys(secretName);
		System.out.println(" (done)");
		final EcPoint publicKey = shareVerificationKeysAndEpoch.getKey().get(0);
		final long currentEpoch = shareVerificationKeysAndEpoch.getValue();
		System.out.println("Public key for secret:    " + publicKey);
		System.out.println("Current epoch for secret: " + currentEpoch);
		System.out.println();

		// Perform distributed Schnorr signature calculation
		System.out.print("Performing threshold Schnorr signature calculation using: " + this.secretName + "... ");
		final byte[] fileDigest = MessageDigest.getInstance("SHA-512").digest(messageBytes);
		// final byte[] signatureBytes = localSign(fileDigest);
		final byte[] signatureBytes = this.computeSignature(fileDigest, currentEpoch,
				shareVerificationKeysAndEpoch.getKey(), publicKey);
		System.out.println(" (done)");
		System.out.println("Signature obtained:    " + HexUtil.binToHex(signatureBytes));
		System.out.println();

		// Write signature result to output file
		System.out.print("Writing signature to file: " + this.signatureFile + "... ");
		Files.write(this.signatureFile.toPath(), signatureBytes);
		System.out.println(" (done)");
		System.out.println("Wrote " + signatureBytes.length + " bytes.");
		System.out.println();

		System.out.println("Done.");
		System.exit(0);

	}

	public void verifyFile() throws BadPaddingException, IllegalBlockSizeException, ClassNotFoundException, IOException,
			ResourceUnavailableException, BelowThresholdException, NoSuchAlgorithmException {

		// Print status
		System.out.println("-----------------------------------------------------------");
		System.out.println("Beginning signature verification for file: " + this.inputFile);

		// Get public key and current epoch from the server
		System.out.print("Accessing public key for secret: " + this.secretName + "... ");
		final SimpleEntry<List<EcPoint>, Long> shareVerificationKeysAndEpoch = this
				.getServerVerificationKeys(secretName);
		System.out.println(" (done)");
		final EcPoint publicKey = shareVerificationKeysAndEpoch.getKey().get(0);
		final long currentEpoch = shareVerificationKeysAndEpoch.getValue();
		System.out.println("Public key for secret:    " + publicKey);
		System.out.println("Current epoch for secret: " + currentEpoch);
		System.out.println();

		// Reading File
		System.out.print("Reading signed file: " + this.inputFile + "... ");
		final byte[] message = Files.readAllBytes(inputFile.toPath());
		System.out.println(" (done)");
		System.out.println("Read " + message.length + " bytes.");
		System.out.println();

		// Reading Signature
		System.out.print("Reading signature: " + this.signatureFile + "... ");
		final byte[] signatureBytes = Files.readAllBytes(signatureFile.toPath());
		System.out.println(" (done)");
		System.out.println("Read " + signatureBytes.length + " bytes.");
		System.out.println();

		// Perform Schnorr signature validation encryption
		System.out.print("Performing Schnorr signature verification of file content... ");

		try {
			final byte[] fileDigest = MessageDigest.getInstance("SHA-512").digest(message);
			// localVerify(fileDigest, signatureBytes);
			SchnorrSignatures.verify(CommonConfiguration.CURVE, MessageDigest.getInstance("SHA-512"),
					publicKey, fileDigest, signatureBytes);
			System.out.println(" (done)");
			System.out.println("Signature is VALID.");
		} catch (SignatureException e) {
			System.out.println(" (done)");
			System.err.println("Signature is <<< INVALID!!! >>>");
			System.exit(1);
		}
		System.out.println();
		System.exit(0);
	}

	public static void main(final String args[]) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException,
			CertificateException, BadPaddingException, IllegalBlockSizeException, ClassNotFoundException,
			ResourceUnavailableException, BelowThresholdException {

		// Parse arguments
		if (args.length < 6) {
			System.err.println("USAGE: config-dir username secretname [SIGN/VERIFY] input-file signature-file");
			System.exit(-1);
		}
		final File baseDirectory = new File(args[0]);
		final String username = args[1];
		final String secretName = args[2];
		final boolean sign = "SIGN".equalsIgnoreCase(args[3]);
		final File inputFile = new File(args[4]);
		final File signatureFile = new File(args[5]);

		if (!inputFile.exists()) {
			System.err.println("Input file does not exist: " + inputFile.getAbsolutePath());
			System.exit(-1);
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

		// Create signature client
		final SchnorrSignatureClient signatureClient = new SchnorrSignatureClient(configuration, caCerts, serverKeys,
				clientCertificate, clientPrivateKey, secretName, inputFile, signatureFile);

		// Perform operation
		if (sign) {
			signatureClient.signFile();
		} else {
			signatureClient.verifyFile();
		}
	}

	/**
	 * Interacts with the servers to to compute a signature for a given message
	 * 
	 * @param messageBytes
	 * @param publicKey
	 * @return
	 * @throws ResourceUnavailableException
	 */
	private byte[] computeSignature(byte[] messageBytes, final long expectedEpoch,
			final List<EcPoint> shareVerificationKeys, final EcPoint publicKey) throws ResourceUnavailableException {

		// Choose a UUID for this signature calculation to reference between the two
		// phases of the protocol
		final UUID nonceCacheId = UUID.randomUUID();

		// Phase 1: Collect the commitments from the servers
		final List<NonceCommitment> commitmentList = collectCommitments(expectedEpoch, nonceCacheId);
		final SortedMap<BigInteger, NonceCommitment> nonceCommitmentMap = SchnorrUtil
				.mapNonceCommitments(commitmentList);

		// Phase 2: Send the collected commitments to each server to obtain its share of
		// the signature
		System.out.println(
				"Received " + nonceCommitmentMap.size() + " commitments from the servers. Proceeding to phase 2...");

		final List<SignatureResponse> signatureContributionsList = collectSignatureContributions(messageBytes,
				expectedEpoch, nonceCacheId, nonceCommitmentMap);
		final TreeSet<SignatureResponse> sortedContributions = new TreeSet<>(signatureContributionsList);

		System.out.println("Received " + sortedContributions.size()
				+ " signature contributions from the servers. Generating signature...");

		// Begin signature reconstruction

		// Determin set of participants
		final BigInteger[] participantIndices = SchnorrUtil.getParticipantIndices(nonceCommitmentMap);

		// Create M || B
		byte[] stringB = SchnorrUtil.serializeNonceCommitments(nonceCommitmentMap);
		byte[] combinedString = Parse.concatenate(messageBytes, stringB);


		// Compute R_i sub values
		final SortedMap<BigInteger, EcPoint> Ris = SchnorrUtil.comptuteRValues(nonceCommitmentMap, combinedString);

		// Compute combined R
		final EcPoint R = SchnorrUtil.sumEcPoints(Ris.values());

		// System.out.println("R: " + R.toString());

		// Compute challenge c = H(R, Y, m)
		final BigInteger challenge = SchnorrUtil.computeChallenge(R, publicKey, messageBytes);

		//System.out.println("c: " + challenge.toString());

		// Verify all the share contributions
		for (SignatureResponse signatureResponse : sortedContributions) {
			final BigInteger participantIndex = BigInteger.valueOf(signatureResponse.getResponderIndex());
			final BigInteger signatureShare = signatureResponse.getSignatureContribution();
			final EcPoint shareholderPublicKey = shareVerificationKeys.get(participantIndex.intValue());
			final EcPoint Ri = Ris.get(participantIndex);

			try {
				SchnorrUtil.verifySignatureShare(participantIndex, participantIndices, shareholderPublicKey,
						signatureShare, challenge, Ri);
			} catch (SignatureException e) {
				System.err.println("Server at index " + participantIndex.toString()
						+ " provided an invalid contribution. Aborting signature attempt. Please notify the administrator.");
				System.exit(1);
				// TODO: Rerun protocol while excluding the server at this index.
			}
		}

		// Interpolate/combine results to produce signature
		BigInteger combinedSignature = BigInteger.ZERO;
		for (final SignatureResponse response : sortedContributions) {
			combinedSignature = combinedSignature.add(response.getSignatureContribution()).mod(SchnorrUtil.MOD);
		}

		return SchnorrUtil.composeSignature(R, combinedSignature);
	}

	/**
	 * Interacts with the servers to collect commitments (first round of signature
	 * calculation)
	 * 
	 * @param messageBytes
	 * @return
	 * @throws ResourceUnavailableException
	 */
	private List<NonceCommitment> collectCommitments(final long expectedEpoch, final UUID nonceCacheId)
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
		final List<Object> verifiedResults = Collections.synchronizedList(new ArrayList<>());

		// Create a partial result task for everyone except ourselves
		int serverId = 0;
		for (final InetSocketAddress serverAddress : this.serverConfiguration.getServerAddresses()) {
			serverId++;
			final String serverIp = serverAddress.getAddress().getHostAddress();
			final int serverPort = CommonConfiguration.BASE_HTTP_PORT + serverId;
			final String linkUrl = "https://" + serverIp + ":" + serverPort + "/schnorr-nonce?secretName="
					+ this.secretName + "&nonce-id=" + nonceCacheId.toString() + "&json=true";

			final int thisServerId = serverId;

			// Create new task to get the nonce commitment results from the servers
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

					final JSONArray dCommitment = (JSONArray) jsonObject.get("gd");
					final BigInteger dx = new BigInteger((String) dCommitment.get(0));
					final BigInteger dy = new BigInteger((String) dCommitment.get(1));

					final JSONArray eCommitment = (JSONArray) jsonObject.get("ge");
					final BigInteger ex = new BigInteger((String) eCommitment.get(0));
					final BigInteger ey = new BigInteger((String) eCommitment.get(1));

					// Verify result
					// TODO: Separate results by their epoch, wait for enough results of the same
					// epoch
					// TOOD: Implement retry if epoch mismatch and below threshold
					if ((responder == thisServerId) && (epoch == expectedEpoch)) {

						final EcPoint dCommitmentPoint = new EcPoint(dx, dy);
						final EcPoint eCommitmentPoint = new EcPoint(ex, ey);

						// Store result for later processing
						verifiedResults.add(new NonceCommitment(thisServerId, dCommitmentPoint, eCommitmentPoint));

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

				List<NonceCommitment> results = verifiedResults.stream().map(obj -> createNonceCommitment(obj))
						.collect(Collectors.toList());

				return results;
			} else {
				executor.shutdown();
				throw new ResourceUnavailableException();
			}
		} catch (InterruptedException e) {
			throw new RuntimeException(e);
		}

	}

	private static SignatureResponse createSignatureResponse(Object obj) {
		return (SignatureResponse) obj;
	}

	private static NonceCommitment createNonceCommitment(Object obj) {
		return (NonceCommitment) obj;
	}

	/**
	 * Interacts with the servers to collect signature contributions and derive
	 * signature (second round of signature calculation)
	 * 
	 * @param messageBytes
	 * @param commitments
	 * @return
	 * @throws ResourceUnavailableException
	 */
	private List<SignatureResponse> collectSignatureContributions(final byte[] messageBytes, final long expectedEpoch,
			final UUID nonceCacheId, final SortedMap<BigInteger, NonceCommitment> commitmentMap)
			throws ResourceUnavailableException {

		// We create a thread pool with a thread for each task and remote server
		final ExecutorService executor = Executors.newFixedThreadPool(commitmentMap.size());

		// The countdown latch tracks progress towards reaching a threshold
		final CountDownLatch latch = new CountDownLatch(commitmentMap.size());
		final AtomicInteger failureCounter = new AtomicInteger(0);
		final int maximumFailures = 0;

		// Each task deposits its result into this map after verifying it is correct and
		// consistent
		final List<Object> verifiedResults = Collections.synchronizedList(new ArrayList<>());

		// Create a partial result task for everyone except ourselves
		int serverId = 0;
		for (final InetSocketAddress serverAddress : this.serverConfiguration.getServerAddresses()) {
			serverId++;

			if (!commitmentMap.containsKey(BigInteger.valueOf(serverId))) {
				continue;
			}

			final String serverIp = serverAddress.getAddress().getHostAddress();
			final int serverPort = CommonConfiguration.BASE_HTTP_PORT + serverId;

			// Compose parameter string of all commitments
			final StringBuffer commitmentParams = new StringBuffer();
			for (final Entry<BigInteger, NonceCommitment> entry : commitmentMap.entrySet()) {
				final NonceCommitment response = entry.getValue();
				commitmentParams
						.append("&dx_" + response.getParticipantIndex() + "=" + response.getCommitmentD().getX());
				commitmentParams
						.append("&dy_" + response.getParticipantIndex() + "=" + response.getCommitmentD().getY());
				commitmentParams
						.append("&ex_" + response.getParticipantIndex() + "=" + response.getCommitmentE().getX());
				commitmentParams
						.append("&ey_" + response.getParticipantIndex() + "=" + response.getCommitmentE().getY());
			}

			final String linkUrl = "https://" + serverIp + ":" + serverPort + "/schnorr-sign?secretName="
					+ this.secretName + "&nonce-id=" + nonceCacheId.toString() + "&message="
					+ HexUtil.binToHex(messageBytes) + commitmentParams.toString() + "&json=true";

			final int thisServerId = serverId;

			// Create new task to get the nonce commitment results from the servers
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

					final BigInteger share = new BigInteger((String) jsonObject.get("share"));

					// Verify result
					// TODO: Separate results by their epoch, wait for enough results of the same
					// epoch
					// TOOD: Implement retry if epoch mismatch and below threshold
					if ((responder == thisServerId) && (epoch == expectedEpoch)) {

						// Store result for later processing
						verifiedResults.add(new SignatureResponse(responder, share));

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

				List<SignatureResponse> results = verifiedResults.stream().map(obj -> createSignatureResponse(obj))
						.collect(Collectors.toList());

				return results;
			} else {
				executor.shutdown();
				throw new ResourceUnavailableException();
			}
		} catch (InterruptedException e) {
			throw new RuntimeException(e);
		}

	}

	public static final class SignatureResponse implements Comparable<SignatureResponse> {
		private final long responderIndex;
		private final BigInteger signatureContribution;

		public SignatureResponse(long responderIndex, BigInteger signatureContribution) {
			super();
			this.responderIndex = responderIndex;
			this.signatureContribution = signatureContribution;
		}

		public long getResponderIndex() {
			return responderIndex;
		}

		public BigInteger getSignatureContribution() {
			return signatureContribution;
		}

		@Override
		public int hashCode() {
			final int prime = 31;
			int result = 1;
			result = prime * result + (int) (responderIndex ^ (responderIndex >>> 32));
			result = prime * result + ((signatureContribution == null) ? 0 : signatureContribution.hashCode());
			return result;
		}

		@Override
		public boolean equals(Object obj) {
			if (this == obj)
				return true;
			if (obj == null)
				return false;
			if (getClass() != obj.getClass())
				return false;
			SignatureResponse other = (SignatureResponse) obj;
			if (responderIndex != other.responderIndex)
				return false;
			if (signatureContribution == null) {
				if (other.signatureContribution != null)
					return false;
			} else if (!signatureContribution.equals(other.signatureContribution))
				return false;
			return true;
		}

		@Override
		public int compareTo(SignatureResponse other) {
			return Long.valueOf(this.responderIndex).compareTo(Long.valueOf(other.responderIndex));
		}

	}


}
