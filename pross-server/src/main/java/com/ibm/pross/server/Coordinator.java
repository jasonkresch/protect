/*
 * Copyright (c) IBM Corporation 2018. All Rights Reserved.
 * Project name: pross
 * This project is licensed under the MIT License, see LICENSE.
 */

package com.ibm.pross.server;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.Security;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.atomic.AtomicLong;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import com.ibm.pross.client.PrfClient;
import com.ibm.pross.common.util.crypto.ecc.EcPoint;
import com.ibm.pross.server.shareholder.Shareholder;

/**
 * This class coordinates functions such as refreshing or reconstructing shares
 */
public class Coordinator {

	// Track shareholders
	private final Shareholder[] shareholders;
	private final Clock clock;

	static {
		Security.addProvider(new BouncyCastleProvider());
	}

	public Coordinator(final Shareholder[] shareholders, final Clock clock) {
		this.shareholders = shareholders;
		this.clock = clock;
	}

	/**
	 * Performs the Joint-Feldman protocol to generate an initial secret sharing
	 * of a random x
	 * 
	 * At the end, all properly behaving shareholders are initialized with a
	 * share of the secret and knowledge of all other shareholder's share public
	 * keys, as well as the public key y corresponding to the secret x.
	 * @throws IOException 
	 * @throws ClassNotFoundException 
	 * @throws IllegalBlockSizeException 
	 * @throws BadPaddingException 
	 */
	public void performDistributedKeyGeneration() throws BadPaddingException, IllegalBlockSizeException, ClassNotFoundException, IOException {

		// Begin

		// Step 1: All shareholders generate new random polynomial with
		// y-intercept of 0
		for (Shareholder shareholder : this.shareholders) {
			shareholder.generateShareGenerationMessages();
		}

		// Step 2: Each shareholder, sends to every other, his evaluation of his
		// random polynomial for that shareholder's x coordinate.
		for (Shareholder shareholder : this.shareholders) {
			shareholder.sendShareGenerationMessages();
		}

		// Step 3: Each shareholder is instructed to verify each of the update
		// messages received by other parties
		for (Shareholder shareholder : this.shareholders) {
			shareholder.verifyGenerationMessages();
		}

		// Step 4: Each shareholder sends accusations regarding corrupt
		// shareholders, or an acceptance (empty list) if everything checks out
		for (Shareholder shareholder : this.shareholders) {
			shareholder.makeGenerationAccusations();
		}

		// Step 5: Each accused shareholder attempts to send a rebuttal to an
		// accusation, in the form of a decrypted value of the accuser
		for (Shareholder shareholder : this.shareholders) {
			shareholder.sendGenerationRebuttals();
		}

		// Step 6: Each shareholder processes all the rebuttals to determine who
		// was lying, updating the internal list of determined corrupted servers
		// to exclude
		for (Shareholder shareholder : this.shareholders) {
			shareholder.processGenerationRebuttles();
		}

		// Step 7: After excluding identified malfunctioning shareholders (from
		// processing accusations and rebuttals) each shareholder determines if
		// it can update its share, if it has at least T honest shareholders, it
		// does so.
		int successCount = 0;
		for (Shareholder shareholder : this.shareholders) {
			if (shareholder.attemptShareGeneration())
				successCount++;
		}
		System.out.println("Successfull share generation count: " + successCount);

		// Step 8:
		// After the update, query all shareholders for who they think is
		// corrupted
		// Use a majority rule, and reset those shareholders or flag them for
		// investigation
		final ConcurrentMap<Integer, AtomicLong> corruptionReports = new ConcurrentHashMap<>();
		for (Shareholder shareholder : this.shareholders) {
			Set<Integer> corruptedShareholders = shareholder.getGenerationCorruptionReport();
			for (Integer corrupted : corruptedShareholders) {
				corruptionReports.putIfAbsent(corrupted, new AtomicLong(0));
				AtomicLong count = corruptionReports.get(corrupted);
				count.incrementAndGet();
			}
		}
		for (Integer shareholder : corruptionReports.keySet()) {
			if (corruptionReports.containsKey(shareholder)) {
				long count = corruptionReports.get(shareholder).get();
				if (count > (this.shareholders.length / 2)) {
					System.out.println("Over half (" + count + ") shareholders reported shareholder [" + shareholder
							+ "] as corrupted! Investigate and repair!");
					// TODO: Reset this shareholder and rebuild it
				}
			}
		}


	}

	/**
	 * "At the beginning of every time period, all honest servers trigger an
	 * update phase"
	 * 
	 * <pre>
	 * This phase consists of three operations, run in series:
	 * 
	 * 1. Dynamic rekeying (all shareholders update signing and encryption keys)
	 * 2. Share reconstruction (shareholders with missing or corrupt shares recover them)
	 * 3. Share refresh (all shareholders update their share to a new form)
	 * </pre>
	 * 
	 * @throws Exception
	 */
	public void performUpdatePhases() throws Exception {

		// New epoch
		this.clock.advanceTime();

		// Perform dynamic update of keys
		// (section 6)
		updateAllKeyPairs();

		// Perform corrupt share detection and reconstruction
		// (section 4.1 and 4.3)
		detectCorruptSharesAndReconstruct();

		// Perform share refresh
		// (section 3.2)
		refreshAllShares();

	}

	/**
	 * From section 6 of PROSS paper
	 * 
	 * @throws Exception
	 */
	protected void updateAllKeyPairs() {

		// TODO: move this adcance time to the single method that does
		// everything
		this.clock.advanceTime();

		// Step 1: All shareholders generate new key pairs
		for (Shareholder shareholder : this.shareholders) {
			shareholder.generateNewKeys();
		}

		// Step 2: Each shareholder, sends to every other their new key pairs
		for (Shareholder shareholder : this.shareholders) {
			shareholder.sendRekeyPayload();
		}

		// Step 3: Each shareholder updates their set of keys
		for (Shareholder shareholder : this.shareholders) {
			final Set<Integer> reportedMalfunctioningServers = shareholder.performKeyUpdate();
			System.out.println("Shareholder [" + shareholder.getIndex() + "] reports " + reportedMalfunctioningServers
					+ " as corrupted, investigate.");

			// TODO: Use a majority vote to reset corrupted shareholders
		}
	}

	/**
	 * From section 4.1 of PROSS paper
	 * 
	 * @throws Exception
	 */
	protected void detectCorruptSharesAndReconstruct() throws Exception {

		// TODO: move this adcance time to the single method that does
		// everything
		this.clock.advanceTime();

		// Step 1: All shareholders define their view of the system
		for (Shareholder shareholder : this.shareholders) {
			shareholder.generateDetectCorruptShareMessage();
		}

		// Step 2: Each shareholder, sends to every other their view
		for (Shareholder shareholder : this.shareholders) {
			shareholder.sendDetectCorruptMessages();
		}

		// Step 3: Each shareholder is instructed to detect corruptions
		for (Shareholder shareholder : this.shareholders) {
			Set<Integer> corrupted = shareholder.determineCorruptShareholders();
			System.out.println("Corrupted shareholders: " + corrupted);
		}

		this.reconstructAll();
	}

	/**
	 * From section 4.3 of PROSS paper
	 * @throws IOException 
	 * @throws ClassNotFoundException 
	 * @throws IllegalBlockSizeException 
	 * @throws BadPaddingException 
	 * 
	 * @throws Exception
	 */
	private void reconstructAll() throws BadPaddingException, IllegalBlockSizeException, ClassNotFoundException, IOException {

		// Reconstruction

		// Step 1:
		// Each shareholder who is not corrupt, generates a random polynomial
		// for each shareholder requiring reconstruction
		for (Shareholder shareholder : this.shareholders) {
			shareholder.createPolynomialUpdateMessages();
		}

		// Step 2:
		// Each shareholder who is not corrupt, sends polynomial
		// contributions for each shareholder needing reconstruction
		for (Shareholder shareholder : this.shareholders) {
			shareholder.sendReconstructionPolynomials();
		}

		// Step 3: Each shareholder verifies the messages received from the
		// non-corrupt shareholders, checking the equations
		for (Shareholder shareholder : this.shareholders) {
			shareholder.verifyReconstructionPolynomials();
		}

		// Step 4: Accusations are made
		for (Shareholder shareholder : this.shareholders) {
			shareholder.makeReconstructionAccusations();
		}

		// Step 5: Rebuttals are sent
		for (Shareholder shareholder : this.shareholders) {
			shareholder.sendReconstructionRebuttals();
		}

		// Step 6: Rebuttals are processed
		for (Shareholder shareholder : this.shareholders) {
			shareholder.processReconstructionRebuttals();
		}

		// Step 7: Rebuttals are processed and valid dealers are determined
		// Instruct shareholders to attempt to generate a reconstruction message
		// if
		// at least a threshold number of valid polynomials were received
		for (final Shareholder shareholder : this.shareholders) {
			shareholder.attemptCreateAndSendShareUpdate();
		}

		// Step 8: Shareholders needing reconstruction verify the received
		// shares are valid
		// and compute their updated shares using at least a threshold number of
		// valid shares
		// all shareholders report whether or not their latest share was rebuilt
		// successfully
		int successCount = 0;
		for (final Shareholder shareholder : this.shareholders) {
			if (shareholder.processContributions()) {
				successCount++;
			}
			// TODO: Use a majority vote of identified corrupt shareholders to
			// reset
		}
		System.out.println("Healthy stores: " + successCount);

	}

	/**
	 * From section 3.2 of PROSS paper
	 * @throws IOException 
	 * @throws ClassNotFoundException 
	 * @throws IllegalBlockSizeException 
	 * @throws BadPaddingException 
	 * 
	 * @throws Exception
	 */
	protected void refreshAllShares() throws BadPaddingException, IllegalBlockSizeException, ClassNotFoundException, IOException {

		// Begin new time period
		this.clock.advanceTime();

		// Begin

		// Step 1: All shareholders generate new random polynomial with
		// y-intercept of 0
		for (Shareholder shareholder : this.shareholders) {
			shareholder.generateShareUpdateMessages();
		}

		// Step 2: Each shareholder, sends to every other, his evaluation of his
		// random polynomial for that shareholder's x coordinate.
		for (Shareholder shareholder : this.shareholders) {
			shareholder.sendShareUpdateMessages();
		}

		// Step 3: Each shareholder is instructed to verify each of the update
		// messages received by other parties
		for (Shareholder shareholder : this.shareholders) {
			shareholder.verifyUpdateMessages();
		}

		// Step 4: Each shareholder sends accusations regarding corrupt
		// shareholders, or an acceptance (empty list) if everything checks out
		for (Shareholder shareholder : this.shareholders) {
			shareholder.makeAccusations();
		}

		// Step 5: Each accused shareholder attempts to send a rebuttal to an
		// accusation, in the form of a decrypted value of the accuser
		for (Shareholder shareholder : this.shareholders) {
			shareholder.sendRebuttals();
		}

		// Step 6: Each shareholder processes all the rebuttals to determine who
		// was lying, updating the internal list of determined corrupted servers
		// to exclude
		for (Shareholder shareholder : this.shareholders) {
			shareholder.processRebuttles();
		}

		// Step 7: After excluding identified malfunctioning shareholders (from
		// processing accusations and rebuttals) each shareholder determines if
		// it can update its share, if it has at least T honest shareholders, it
		// does so.
		int successCount = 0;
		for (Shareholder shareholder : this.shareholders) {
			if (shareholder.attemptShareUpdate())
				successCount++;
		}
		System.out.println("Successfull share update count: " + successCount);

		// Step 8:
		// After the update, query all shareholders for who they think is
		// corrupted
		// Use a majority rule, and reset those shareholders or flag them for
		// investigation
		final ConcurrentMap<Integer, AtomicLong> corruptionReports = new ConcurrentHashMap<>();
		for (Shareholder shareholder : this.shareholders) {
			Set<Integer> corruptedShareholders = shareholder.getCorruptionReport();
			for (Integer corrupted : corruptedShareholders) {
				corruptionReports.putIfAbsent(corrupted, new AtomicLong(0));
				AtomicLong count = corruptionReports.get(corrupted);
				count.incrementAndGet();
			}
		}
		for (Integer shareholder : corruptionReports.keySet()) {
			if (corruptionReports.containsKey(shareholder)) {
				long count = corruptionReports.get(shareholder).get();
				if (count > (this.shareholders.length / 2)) {
					System.out.println("Over half (" + count + ") shareholders reported shareholder [" + shareholder
							+ "] as corrupted! Investigate and repair!");
					// TODO: Reset this shareholder and rebuild it
				}
			}
		}

	}

	public static void main2(String[] args) throws Exception {

		// Create threshold parameters
		final int n = 5;
		final int updateThreshold = 4;
		final int threshold = 3;

		final Administration administration = new Administration(n, threshold, updateThreshold, false);
		final Coordinator coordinator = administration.getCoordinator();
		
		// Create T-OPRF client
		final PrfClient prfClient = administration.provisionClient();

		// Wrap and unwrap a key
		final byte[] input = "5UP3R5ECR3T INPUT".getBytes(StandardCharsets.UTF_8);
		final EcPoint point1 = prfClient.derivePointFromBytes(input);
		
		final EcPoint point2 = prfClient.derivePointFromBytes(input);
		System.out.println("Recovered Output: " + point1);
		if (!point1.equals(point2)) {
			throw new RuntimeException("Failed to recover same output");
		}

		// Heal system and refresh shares
		coordinator.performUpdatePhases();

		// Ensure we can still unwrap previously wrapped keys
		final EcPoint point3 = prfClient.derivePointFromBytes(input);
		System.out.println("Recovered Output " + point3);
		if (!point1.equals(point3)) {
			throw new RuntimeException("Failed to recover same output");
		}
	}


	public static void main(String[] args) throws Exception {

		// Create threshold parameters
		final int n = 4;
		final int updateThreshold = 3;
		final int threshold = 3;

		final Administration administration = new Administration(n, threshold, updateThreshold, true);
		final Coordinator coordinator = administration.getCoordinator();
		
		try {
			Thread.sleep(5000);
		} catch (InterruptedException e) {
			throw new RuntimeException("interrupted", e);
		}
		
		// Create T-OPRF client
		final PrfClient prfClient = administration.provisionClient();

		// Wrap and unwrap a key
		final byte[] input = "5UP3R5ECR3T INPUT".getBytes(StandardCharsets.UTF_8);
		final EcPoint point1 = prfClient.derivePointFromBytes(input);
		
		final EcPoint point2 = prfClient.derivePointFromBytes(input);
		System.out.println("Recovered Output: " + point1);
		if (!point1.equals(point2)) {
			throw new RuntimeException("Failed to recover same output");
		}

		// Heal system and refresh shares
		coordinator.performUpdatePhases();

		// Ensure we can still unwrap previously wrapped keys
		final EcPoint point3 = prfClient.derivePointFromBytes(input);
		System.out.println("Recovered Output " + point3);
		if (!point1.equals(point3)) {
			throw new RuntimeException("Failed to recover same output");
		}
	}
	
}
