package com.ibm.pross.common.util.crypto.rsa.threshold.sign.client;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;

import com.ibm.pross.common.config.CommonConfiguration;
import com.ibm.pross.common.util.Exponentiation;
import com.ibm.pross.common.util.RandomNumberGenerator;
import com.ibm.pross.common.util.crypto.rsa.RsaUtil;
import com.ibm.pross.common.util.crypto.rsa.threshold.sign.data.SignatureResponse;
import com.ibm.pross.common.util.crypto.rsa.threshold.sign.exceptions.BadArgumentException;
import com.ibm.pross.common.util.crypto.rsa.threshold.sign.exceptions.BelowThresholdException;
import com.ibm.pross.common.util.crypto.rsa.threshold.sign.exceptions.SecretRecoveryException;
import com.ibm.pross.common.util.crypto.rsa.threshold.sign.exceptions.UserNotFoundException;
import com.ibm.pross.common.util.crypto.rsa.threshold.sign.math.ThresholdSignatures;
import com.ibm.pross.common.util.crypto.rsa.threshold.sign.server.RsaSignatureServer;
import com.ibm.pross.common.util.crypto.rsa.threshold.sign.server.ServerPublicConfiguration;

/**
 * Recovers an RSA signature via interaction with at least a threshold number of
 * well-behaved servers.
 * 
 * Improperly behaving servers are detected through a verification process and
 * are excluded from the operation. This recovery operation can be used to
 * reliably store small amounts of data that is highly sensitive and highly
 * valuable, necessitating strong confidentiality and long-term availability
 * properties.
 */
public class RsaSignatureClient {

	private final RsaSignatureServer[] servers;
	private final int threshold;

	public RsaSignatureClient(RsaSignatureServer[] servers, int threshold) {
		this.servers = servers;
		this.threshold = threshold;
	}

	public BigInteger recoverSignature(final String keyName, final byte[] toBeSigned) throws BelowThresholdException, BadArgumentException, SecretRecoveryException, NoSuchAlgorithmException {

		// Use a quorum to establish the consistent configuration across servers
		final ServerPublicConfiguration mostCommonConfig = RsaSignatureClient.getConsistentConfiguration(keyName, this.servers,
				this.threshold);

		// Generate blinded version of the password
		System.out.print("  Computing a blinded password...");
		BigInteger n = mostCommonConfig.getN();
		BigInteger e = mostCommonConfig.getE();
		BigInteger r = RandomNumberGenerator.generateRandomInteger(n);
		BigInteger b = r.modPow(e, n);
		
		// Process to message to be signed by hashing
		final byte[] hashed = MessageDigest.getInstance(CommonConfiguration.HASH_ALGORITHM).digest(toBeSigned);
		BigInteger numToBeSigned = (new BigInteger(1, hashed)).mod(n);
		
		// Blind the input to be signed
		BigInteger blindedToBeSigned = numToBeSigned.multiply(b).mod(n);
		System.out.println(" done.");

		// Send signing request to the servers
		System.out.print("  Requesting signature shares of blinded password...");
		Set<SignatureResponse> signatureTriplets = new HashSet<>();
		int serverIndex = 0;
		for (RsaSignatureServer server : servers) {
			serverIndex++;
			try {
				signatureTriplets.add(server.computeSignatureShare(keyName, blindedToBeSigned));
			} catch (BadArgumentException | UserNotFoundException e1) {
				System.out
						.print("    Failed to get result from server[" + serverIndex + "], error = " + e1.getMessage());
			}
		}
		System.out.println(" done. Collected " + signatureTriplets.size() + " unique signature shares");

		System.out.println("  Verifying signature shares...");
		
		// Validate each share and remove it if it doesn't pass verification
		List<SignatureResponse> validatedSignatureTriplets = new ArrayList<>();
		for (SignatureResponse signatureTriplet : signatureTriplets) {

			BigInteger index = signatureTriplet.getServerIndex();

			try {
				if (ThresholdSignatures.validateSignatureResponse(blindedToBeSigned, signatureTriplet, mostCommonConfig)) {
					validatedSignatureTriplets.add(signatureTriplet);
				} else {
					System.out.println(
							"    Signture share at index " + index + " failed validation, excluding from operation");
				}
			} catch (BadArgumentException e1) {
				System.out.println(
						"    Signture share at index " + index + " failed validation, excluding from operation, error = " + e1.getMessage());
			}
		}

		System.out.println("  Recovered " + validatedSignatureTriplets.size() + " verified signature shares");

		if (validatedSignatureTriplets.size() < this.threshold) {
			throw new BelowThresholdException("Insufficient valid signature shares to recover (below threshold)");
		}

		// Combine shares
		System.out.print("  Recovering signature from shares...");
		BigInteger blindedSignature = ThresholdSignatures.recoverSignature(blindedToBeSigned, validatedSignatureTriplets,
				mostCommonConfig);
		System.out.println(" done.");

		// Verify signature is correct for what was passed
		System.out.print("  Verifying signature...");
		BigInteger signed = RsaUtil.rsaVerify(blindedSignature, e, n);
		if (!signed.equals(blindedToBeSigned)) {
			throw new SecretRecoveryException("Signature was improperly computed");
		}
		System.out.println(" done.");

		// Unblind the signature
		System.out.print("  Unblinding signature...");
		BigInteger unblindingFactor = Exponentiation.modInverse(r, n);
		BigInteger signatureOfPassword = blindedSignature.multiply(unblindingFactor).mod(n);
		System.out.println(" done.");

		return signatureOfPassword;
	}

	public static ServerPublicConfiguration getConsistentConfiguration(final String username, final RsaSignatureServer[] servers,
			int threshold) throws BelowThresholdException {

		System.out.print("  Accessing configuration information from servers...");
		// Begin with by requesting configuration from all servers
		final Map<ServerPublicConfiguration, Integer> serverConfigs = new HashMap<>();
		for (RsaSignatureServer server : servers) {
			try {
				ServerPublicConfiguration config = server.getPublicConfiguration(username);
				if (!serverConfigs.containsKey(config)) {
					serverConfigs.put(config, 1);
				} else {
					Integer currentCount = serverConfigs.get(config);
					serverConfigs.put(config, new Integer(currentCount + 1));
				}
			} catch (Exception e) {
				System.out.print("  Failed to recover from one server..");
			}
		}
		System.out.println(" done.");

		// Determine which view is the most consistent
		ServerPublicConfiguration mostCommonConfig = null;
		int maxConsistencies = 0;
		for (Entry<ServerPublicConfiguration, Integer> entry : serverConfigs.entrySet()) {
			if (entry.getValue() > maxConsistencies) {
				maxConsistencies = entry.getValue();
				mostCommonConfig = entry.getKey();
			}
		}
		System.out.println("  Found configuration shared by " + maxConsistencies + " servers");

		if (maxConsistencies < threshold) {
			throw new BelowThresholdException("Insufficient consistency to permit recovery (below threshold)");
		}

		return mostCommonConfig;
	}

}
