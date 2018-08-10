/*
 * Copyright (c) IBM Corporation 2018. All Rights Reserved.
 * Project name: pross
 * This project is licensed under the MIT License, see LICENSE.
 */

package com.ibm.pross.server.shareholder.state;

import java.math.BigInteger;
import java.security.PrivateKey;
import java.util.AbstractMap.SimpleEntry;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.SortedSet;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

import com.ibm.pross.common.CommonConfiguration;
import com.ibm.pross.common.util.crypto.EciesEncryption;
import com.ibm.pross.common.util.crypto.ecc.EcCurve;
import com.ibm.pross.common.util.crypto.ecc.EcPoint;
import com.ibm.pross.common.util.shamir.Polynomials;
import com.ibm.pross.common.util.shamir.Shamir;
import com.ibm.pross.common.util.shamir.ShamirShare;
import com.ibm.pross.server.Channel;
import com.ibm.pross.server.messages.EncryptedPayload;
import com.ibm.pross.server.messages.Message;
import com.ibm.pross.server.messages.Payload;
import com.ibm.pross.server.messages.SemiPrivateMessage;
import com.ibm.pross.server.messages.SignedMessage;
import com.ibm.pross.server.messages.payloads.VssPrivatePayload;
import com.ibm.pross.server.messages.payloads.reconstruction.ReconstructionAccusations;
import com.ibm.pross.server.messages.payloads.reconstruction.ReconstructionContribution;
import com.ibm.pross.server.messages.payloads.reconstruction.ReconstructionRebuttal;
import com.ibm.pross.server.messages.payloads.reconstruction.ReconstructionVssPublicPayload;
import com.ibm.pross.server.shareholder.Shareholder;

public class ReconstructShareStateTracker {

	// Static fields
	final public static EcCurve curve = CommonConfiguration.CURVE;
	final public static BigInteger r = curve.getR();
	final public static EcPoint G = curve.getG();

	// Shareholder who is managing this state
	final Shareholder shareholder;

	// Messages
	final SignedMessage ourSignedUpdateMessage;
	final ConcurrentMap<Integer, SignedMessage> receivedMessages = new ConcurrentHashMap<>();
	final SortedSet<Integer> ourAccusations = new TreeSet<>();
	final ConcurrentMap<Integer, ReconstructionAccusations> receivedAccusations = new ConcurrentHashMap<>();
	final ConcurrentMap<SimpleEntry<Integer, Integer>, ReconstructionRebuttal> receivedRebuttals = new ConcurrentHashMap<>();
	final ConcurrentMap<Integer, ShamirShare> receivedContributions = new ConcurrentHashMap<>();

	// Parameters related to current time of operation
	private final long timePeriod;
	private final int corruptedShareholderIndex;
	private final SortedSet<Integer> ourDetectedCorruptions;

	// Parameters related to threshold
	private final int threshold;
	private final int n;

	// Internal state for update operation created by us
	private final EcPoint[] coefficientPowers;

	enum States {
		INITALIZED, SENT_UPDATE, RECEIVED_UPDATES, VERIFIED_UPDATES, MADE_ACCUSATIONS, SENT_REBUTTALS, PROCESSED_REBUTTALS, IDENTIFIED_CORRUPTIONS, ACHIEVED_UPDATE_THRESHOLD, SENT_CONTRIBUTION, REBUILT_SHARE;
	}

	private volatile States currentState;

	public ReconstructShareStateTracker(final Shareholder shareholder, final long timePeriod, final int threshold,
			final int updateThreshold, final int n, final int corruptedShareholderIndex,
			final SortedSet<Integer> ourDetectedCorruptions) {

		this.shareholder = shareholder;
		this.timePeriod = timePeriod;
		this.corruptedShareholderIndex = corruptedShareholderIndex;

		this.ourDetectedCorruptions = ourDetectedCorruptions;

		this.threshold = threshold;
		this.n = n;

		// Section 4.3

		// Generate co-efficients of a random t-1 degree polynomial with
		// y-intercept of 0 at the position of the corrupt shareholder index
		final BigInteger[] coefficients = Shamir.generateCoefficients(threshold, corruptedShareholderIndex + 1);

		// Produce partial shares for everyone else
		final ShamirShare[] ourMaskingShares = Shamir.generateShares(coefficients, this.n);

		// polynomial coefficients times G -- (G^f_i) the feldmen proofs, for
		// all co-efficients including 0
		this.coefficientPowers = Shamir.generateFeldmanValues(coefficients);

		// Build a single semi-private message, to be sent as part of our update
		// for this shareholder
		// Here we do not skip sending the free coefficient
		final ReconstructionVssPublicPayload publicPayload = new ReconstructionVssPublicPayload(timePeriod,
				corruptedShareholderIndex, this.coefficientPowers);

		final Map<Integer, Payload> privatePayloads = new TreeMap<>();

		for (int i = 0; i < n; i++) {
			privatePayloads.put(i, new VssPrivatePayload(ourMaskingShares[i]));
		}

		final Message unsignedMessage = this.shareholder.createSemiPrivateMessage(publicPayload, privatePayloads);
		this.ourSignedUpdateMessage = this.shareholder.createSignedMessage(unsignedMessage);

		this.currentState = States.INITALIZED;
	}

	public SignedMessage getOurSignedUpdateMessage() {
		return ourSignedUpdateMessage;
	}

	public synchronized void sendOurSignedUpdateMessage(final Channel channel) {
		if (this.currentState.equals(States.INITALIZED)) {

			// Only send an update if we're not one of the corrupt shareholders
			if (!this.ourDetectedCorruptions.contains(this.shareholder.getIndex())) {
				channel.broadcast(this.ourSignedUpdateMessage);
			}

			this.currentState = States.SENT_UPDATE;
		} else {
			throw new IllegalStateException("Must be in States.INITIALIZED");
		}
	}

	/**
	 * Persist all received messages
	 * 
	 * @param sender
	 * @param signedMessage
	 * @param decryptionKey
	 */
	public void saveVssMessage(int sender, final SignedMessage signedMessage, final PrivateKey decryptionKey) {

		if (!(this.currentState.equals(States.SENT_UPDATE) || this.currentState.equals(States.INITALIZED))) {
			throw new IllegalStateException("Must be in States.SENT_UPDATE or States.INITIALIZED");
		}

		final SignedMessage previous = this.receivedMessages.putIfAbsent(sender, signedMessage);

		if (previous != null) {
			// Received duplicate message from this sender!
			System.err.println(
					"Shareholder [" + this.shareholder.getIndex() + "] received duplicate messages [" + sender + "]");
			this.ourAccusations.add(sender);
		}

		// Checks to perform

		// Note: Signature checks already performed, we ignore messages with bad
		// signatures
		final SemiPrivateMessage message = (SemiPrivateMessage) signedMessage.getMessage();

		final ReconstructionVssPublicPayload vssPublic = (ReconstructionVssPublicPayload) message.getPublicPayload();

		// Ensure the timestamp in the message matches ours
		if (vssPublic.getUpdateTime() != this.timePeriod) {
			System.err.println("Shareholder [" + this.shareholder.getIndex()
					+ "] send update message from invalid time period [" + sender + "]");
			this.ourAccusations.add(sender);
		}

		// Note, we should have already checked the corruptShareholder index to
		// get here, but just for sanity:
		if (vssPublic.getCorruptShareholder() != this.corruptedShareholderIndex) {
			throw new RuntimeException("Something went wrong!");
		}

		// Ensure the sender is not from the set of identified corrupt
		// shareholders
		if (this.ourDetectedCorruptions.contains(message.getSenderIndex())) {
			System.err.println("Shareholder [" + this.shareholder.getIndex()
					+ "] should not be participating in this operation [" + sender + "]");
			this.ourAccusations.add(sender);
		}

		// Expected number of Feldman parameters present (T)
		if (vssPublic.getFeldmanValues().length != this.threshold) {
			// Incorrect number of feldman values
			System.err.println(
					"Shareholder [" + this.shareholder.getIndex() + "] not enough feldman values [" + sender + "]");
			this.ourAccusations.add(sender);
		}

		// Expected number of private values (N)
		// No duplicate entries of private values (all unique, 0 to N-1)
		for (int i = 0; i < this.n; i++) {
			final EncryptedPayload encryptedPayload = (EncryptedPayload) message.getEncryptedPayload(i);
			if (encryptedPayload == null) {
				// Incorrect number of encrypted values (some recipient didn't
				// get theirs)
				System.err.println(
						"Shareholder [" + this.shareholder.getIndex() + "] not enough recipients [" + sender + "]");
				this.ourAccusations.add(sender);
			}

			if (i == this.shareholder.getIndex()) {
				// This is ours, we can try to decrypt it
				try {
					final Payload privatePayload = EciesEncryption.decryptPayload(encryptedPayload, decryptionKey);
					final VssPrivatePayload vssPrivate = (VssPrivatePayload) privatePayload;
					if ((vssPrivate.getShareUpdate().getX().intValue() - 1) != this.shareholder.getIndex()) {
						// Invalid x coordinate of share
						System.err.println("Shareholder [" + this.shareholder.getIndex()
								+ "] invalid share update from [" + sender + "]");
						this.ourAccusations.add(sender);
					}
					if (vssPrivate.getShareUpdate().getY().compareTo(BigInteger.ZERO) < 0) {
						// Invalid y coordinate of share, it is negative!
						System.err.println("Shareholder [" + this.shareholder.getIndex()
								+ "] invalid share update from [" + sender + "]");
						this.ourAccusations.add(sender);
					}
					if (vssPrivate.getShareUpdate().getY().compareTo(r) >= 0) {
						// Invalid y coordinate of share, it is too big!
						System.err.println("Shareholder [" + this.shareholder.getIndex()
								+ "] invalid share update from [" + sender + "]");
						this.ourAccusations.add(sender);
					}

					// Perform feldman-based verification of our share update!
					Shamir.verifyShamirShareConsistency(vssPrivate.getShareUpdate(), vssPublic.getFeldmanValues());

					// Verify feldman co-efficients are consistent with
					// f(corrupt_index) == 0
					ShamirShare zeroIntercept = new ShamirShare(BigInteger.valueOf(corruptedShareholderIndex + 1),
							BigInteger.ZERO);
					Shamir.verifyShamirShareConsistency(zeroIntercept, vssPublic.getFeldmanValues());

				} catch (IllegalArgumentException e) {
					// Our share is inconsistent with the feldman verification
					System.err.println("Shareholder [" + this.shareholder.getIndex() + "] sent us an invalid share ["
							+ sender + "]");
					this.ourAccusations.add(sender);
				} catch (Exception e) {
					// Failed to decrypt with our public key, need to make a
					// public accusation
					// Or it could be a cast error (in any case we need to force
					// them to make rebuttle)
					System.err.println("Shareholder [" + this.shareholder.getIndex()
							+ "] failed to decrypt share update from [" + sender + "]");
					this.ourAccusations.add(sender);
				}
			}
		}

		// Ignore messages that are missing (Shareholder may be offline)
	}

	public synchronized void verifyUpdateMessages() {

		if (this.currentState.equals(States.SENT_UPDATE)) {
			this.currentState = States.RECEIVED_UPDATES;

			// Filter all of our saved messages according to accusations
			for (Integer accused : this.ourAccusations) {
				this.receivedMessages.remove(accused);
			}

			this.currentState = States.VERIFIED_UPDATES;

		} else {
			throw new IllegalStateException("Must be in States.SENT_UPDATE");
		}

	}

	public synchronized void sendAccusations() {
		if (this.currentState.equals(States.VERIFIED_UPDATES)) {

			// Construct accusation message
			ReconstructionAccusations accusationPayload = new ReconstructionAccusations(this.timePeriod,
					this.corruptedShareholderIndex, this.ourAccusations);

			this.shareholder.sendPublicMessage(accusationPayload);

			this.currentState = States.MADE_ACCUSATIONS;
		} else {
			throw new IllegalStateException("Must be in States.VERIFIED_UPDATES");
		}

	}

	public void saveAccusation(final int sender, final ReconstructionAccusations accusations) {

		if (!(this.currentState.equals(States.MADE_ACCUSATIONS) || this.currentState.equals(States.VERIFIED_UPDATES))) {
			throw new IllegalStateException("Must be in State.VERIFIED_UPDATES or States.MADE_ACCUSATIONS");
		}

		if (accusations.getUpdateTime() == this.timePeriod) {
			this.receivedAccusations.putIfAbsent(sender, accusations);
		} else {
			// An attacker might have recorded and saved this from a previous
			// time period
			// Ignore it
		}
	}

	public synchronized void sendRebuttles() {

		if (this.currentState.equals(States.MADE_ACCUSATIONS)) {
			this.currentState = States.SENT_REBUTTALS;

			// Determine if any accusations were made against us, and if so,
			// send a
			// rebuttal by disclosing the secret AES key used to wrap the
			// recipient's share
			final SemiPrivateMessage semiPrivateMessage = (SemiPrivateMessage) this.getOurSignedUpdateMessage()
					.getMessage();

			for (final Integer accuser : this.receivedAccusations.keySet()) {
				final Set<Integer> accused = this.receivedAccusations.get(accuser).getAccused();
				if (accused.contains(this.shareholder.getIndex())) {

					// We've been accused! Send a public rebuttal.
					final byte[] keyAndNonce = semiPrivateMessage.getEncryptedPayload(accuser).rebuttalEvidence;
					this.shareholder.sendPublicMessage(new ReconstructionRebuttal(this.timePeriod,
							this.corruptedShareholderIndex, accuser, keyAndNonce));

				}
			}

		} else {
			throw new IllegalStateException("Must be in States.MADE_ACCUSATIONS");
		}

	}

	public void saveRebuttal(final int sender, final ReconstructionRebuttal rebuttal) {

		if (!(this.currentState.equals(States.MADE_ACCUSATIONS) || this.currentState.equals(States.SENT_REBUTTALS))) {
			throw new IllegalStateException("Must be in State.SENT_REBUTTALS or States.MADE_ACCUSATIONS");
		}

		if (rebuttal.getUpdateTime() == this.timePeriod) {
			final int accuser = rebuttal.getAccuser();

			final SimpleEntry<Integer, Integer> senderAccuserPair = new SimpleEntry<>(sender, accuser);

			this.receivedRebuttals.putIfAbsent(senderAccuserPair, rebuttal);
		} else {
			// An attacker might have recorded and saved this from a previous
			// time period
			// Ignore it
		}

	}

	public synchronized void processRebuttles() {

		if (this.currentState.equals(States.SENT_REBUTTALS)) {

			// For each accusation, see if a rebuttal was received
			for (final Integer accuserId : this.receivedAccusations.keySet()) {
				final Set<Integer> accused = this.receivedAccusations.get(accuserId).getAccused();
				for (Integer defenderId : accused) {
					// Shareholder i, has accused shareholder j.
					// Look for a rebuttal from shareholder j for shareholder
					// i's claim

					// We haven't already accused j, we need to see if
					// shareholder_i or shareholder_j is lying

					// First, see if a rebuttal was given, if not we side with
					// the accuser
					final SimpleEntry<Integer, Integer> senderAccuserPair = new SimpleEntry<>(defenderId, accuserId);
					if (!this.receivedRebuttals.containsKey(senderAccuserPair)) {
						// No rebuttal, provided, side with the accuser
						this.ourAccusations.add(defenderId);
					} else {
						// Rebuttal was given, see if it checks out
						final ReconstructionRebuttal rebuttal = this.receivedRebuttals.get(senderAccuserPair);

						try {

							// Get the accused's message
							final SemiPrivateMessage defendersMessage = (SemiPrivateMessage) this.receivedMessages
									.get(defenderId).getMessage();

							// Get accuser's encrypted payload
							final EncryptedPayload encryptedPayload = defendersMessage.getEncryptedPayload(accuserId);

							// Decrypt the encrypted message the accused sent to
							// the accuser
							final byte[] keyAndNonce = rebuttal.getRebuttalEvidence();

							final VssPrivatePayload privatePayload = (VssPrivatePayload) EciesEncryption.decryptPayload(
									encryptedPayload, keyAndNonce,
									this.shareholder.getOtherShareholderEncryptionPublicKey(accuserId));

							// Perform checks

							if ((privatePayload.getShareUpdate().getX().intValue() - 1) != accuserId) {
								// Invalid x coordinate of share
								throw new IllegalArgumentException("Invalid x value in share");
							}
							if (privatePayload.getShareUpdate().getY().compareTo(BigInteger.ZERO) < 0) {
								// Invalid y coordinate of share, it is
								// negative!
								throw new IllegalArgumentException("Negative y value in share");
							}
							if (privatePayload.getShareUpdate().getY().compareTo(r) >= 0) {
								// Invalid y coordinate of share, it is too big!
								throw new IllegalArgumentException("y value in share is too large");
							}

							// Perform feldman-based verification of our share
							// update!
							Shamir.verifyShamirShareConsistency(privatePayload.getShareUpdate(),
									((ReconstructionVssPublicPayload) defendersMessage.getPublicPayload())
											.getFeldmanValues());

							// Verify feldman co-efficients are consistent with
							// f(corrupt_index) == 0
							ShamirShare zeroIntercept = new ShamirShare(
									BigInteger.valueOf(corruptedShareholderIndex + 1), BigInteger.ZERO);
							Shamir.verifyShamirShareConsistency(zeroIntercept,
									((ReconstructionVssPublicPayload) defendersMessage.getPublicPayload())
											.getFeldmanValues());

							// Everything checks out, the accuser is lying
							System.err.println("Accusation is false, we are excluding [" + accuserId + "]");
							this.ourAccusations.add(accuserId);

						} catch (Exception e) {
							// Something went wrong, side with the accuser
							System.err.println("Accusation is valid, we are excluding [" + defenderId + "]");
							this.ourAccusations.add(defenderId);
						}
					}
				}
			}

			this.currentState = States.PROCESSED_REBUTTALS;

		} else {
			throw new IllegalStateException("Must be in States.MADE_ACCUSATIONS");
		}
	}

	protected void createAndSendRebuildShareContribution(final ShamirShare share, final PrivateKey decryptionKey) {
		if (this.currentState == States.PROCESSED_REBUTTALS) {
			this.currentState = States.SENT_CONTRIBUTION;

			// Filter all remaining messages based on our updated accusations
			for (final Integer corruptServer : this.ourAccusations) {
				this.receivedMessages.remove(corruptServer);
			}

			// Filter all messages based on previously determined corruptions
			for (final Integer corruptServer : this.ourDetectedCorruptions) {
				this.receivedMessages.remove(corruptServer);
			}

			// If we are corrupt ourselves, then skip
			if (this.ourDetectedCorruptions.contains(this.shareholder.getIndex())) {
				return;
			}

			// Check if we are over threshold
			if (this.receivedMessages.size() >= this.threshold) {

				// Compute our reconstruction contribution share
				BigInteger updateSum = BigInteger.ZERO;
				for (final Integer sender : this.receivedMessages.keySet()) {

					// Decrypt our private component from one of the valid
					// shareholders
					final SemiPrivateMessage message = (SemiPrivateMessage) this.receivedMessages.get(sender)
							.getMessage();
					final EncryptedPayload encryptedPayload = message.getEncryptedPayload(this.shareholder.getIndex());
					final VssPrivatePayload privatePayload = (VssPrivatePayload) EciesEncryption
							.decryptPayload(encryptedPayload, decryptionKey);

					updateSum = updateSum.add(privatePayload.getShareUpdate().getY().mod(r));
				}

				final ShamirShare maskedShare = new ShamirShare(share.getX(), share.getY().add(updateSum).mod(r));

				// Create and send a private reconstruction message for the
				// corrupted recipient
				final ReconstructionContribution contribution = new ReconstructionContribution(this.timePeriod,
						maskedShare);
				this.shareholder.sendPrivateMessage(corruptedShareholderIndex, contribution);

			} else {
				System.err.println("Below threshold, unable to rebuild! [" + this.shareholder.getIndex() + "]");
			}

		} else {
			throw new IllegalStateException("Must be in States.PROCESSED_REBUTTALS");
		}
	}

	public void saveReconstructionContribution(final int sender,
			final ReconstructionContribution reconstructionContribution) {

		if (!(this.currentState.equals(States.PROCESSED_REBUTTALS)
				|| this.currentState.equals(States.SENT_CONTRIBUTION))) {
			throw new IllegalStateException("Must be in State.PROCESSED_REBUTTALS or States.SENT_CONTRIBUTION");
		}

		// Perform all polynomial based verifications of this share
		final ShamirShare contribution = reconstructionContribution.getShareUpdate();

		// Ensure the sender is not excluded
		if (this.ourAccusations.contains(sender) || this.ourDetectedCorruptions.contains(sender)) {
			System.err.println("Received contribution from excluded shareholder [" + sender + "]");
			return;
		}

		// Ensure sender id matches expected x
		if (contribution.getX().intValue() != (sender + 1)) {
			System.err.println("Received bad share from shareholder [" + sender + "]");
			return;
		}

		// Ensure y value is within expected bounds
		if (contribution.getY().compareTo(BigInteger.ZERO) < 0) {
			System.err.println("Received bad share from shareholder [" + sender + "], y is negative");
			return;
		}

		// Ensure y value is within expected bounds
		if (contribution.getY().compareTo(r) >= 0) {
			System.err.println("Received bad share from shareholder [" + sender + "], y is greater than modulus");
			return;
		}

		// Save the share
		final ShamirShare previous = receivedContributions.putIfAbsent(sender,
				reconstructionContribution.getShareUpdate());
		if (previous != null) {
			System.err.println("Received duplicate updates from shareholder [" + sender + "]");
			this.ourAccusations.add(sender);
		}

	}

	public synchronized ShamirShare processReconstructionContributions() {

		if (this.currentState == States.SENT_CONTRIBUTION) {
			this.currentState = States.REBUILT_SHARE;

			// Ensure we are the corrupt shareholder
			if (corruptedShareholderIndex != this.shareholder.getIndex()) {
				throw new RuntimeException("This method should not be called");
			}

			// Ensure there are at least a threshold number of valid responses
			if (this.receivedMessages.size() < this.threshold) {
				System.err.println("We never received a threshold number of valid messages");
				return null;
			}

			// Filter any newly excluded results who may have double-sent
			// messages
			for (Integer accused : this.ourAccusations) {
				this.receivedContributions.remove(accused);
			}

			// Filter any received contributions we don't have a received
			// message for
			for (final Integer contributor : this.receivedContributions.keySet()) {
				if (!this.receivedMessages.containsKey(contributor)) {
					this.receivedContributions.remove(contributor);
				}
			}

			// Ensure there are at least a threshold number of valid
			// contributions
			if (this.receivedContributions.size() < this.threshold) {
				System.err.println("We never received a threshold number of valid contributions");
				return null;
			}

			// Perform polynomial based verification of the received shares
			final EcPoint[] expectedShareUpdatePowers = new EcPoint[this.n];
			for (int i = 0; i < n; i++) {
				expectedShareUpdatePowers[i] = this.shareholder.getSharePublicKeys()[i];
			}

			// Create a combined sum of published Feldman values which we can
			// use to verify received contributions
			for (final Integer sender : this.receivedMessages.keySet()) {
				final SemiPrivateMessage message = (SemiPrivateMessage) this.receivedMessages.get(sender).getMessage();

				// Get feldman values from message
				final ReconstructionVssPublicPayload vssPublicPayload = (ReconstructionVssPublicPayload) message
						.getPublicPayload();
				final EcPoint[] feldmanValues = vssPublicPayload.getFeldmanValues();

				// Compute updates for each shareholder form the feldman
				// values
				final EcPoint[] updates = Shamir.computeSharePublicKeys(feldmanValues, this.n);

				// Update each shareholder with the updates from this
				// message
				for (int i = 0; i < n; i++) {
					expectedShareUpdatePowers[i] = curve.addPoints(expectedShareUpdatePowers[i], updates[i]);
				}
			}

			// Compare our received shares against the computed Feldman sums
			final Set<ShamirShare> verifiedShamirShares = new HashSet<>();
			for (final ShamirShare share : receivedContributions.values()) {

				final EcPoint expectedSharePower = expectedShareUpdatePowers[share.getX().intValue() - 1];
				final EcPoint actualSharePower = curve.multiply(G, share.getY());
				if (expectedSharePower.equals(actualSharePower)) {
					verifiedShamirShares.add(share);
				} else {
					System.err
							.println("Received corrupt share from shareholder [" + (share.getX().intValue() - 1) + "]");
				}
			}

			if (verifiedShamirShares.size() < this.threshold) {
				System.err.println("Not enough valid shares to rebuild!");
				return null;
			}

			// Recover our share
			final BigInteger recoveredY = Polynomials.interpolateComplete(verifiedShamirShares, threshold,
					corruptedShareholderIndex + 1);

			// Recover our public key from the rebuilt share to verify
			final EcPoint recoveredPublicKey = curve.multiply(G, recoveredY);

			final EcPoint expectedPublicKey = this.shareholder.getSharePublicKeys()[this.corruptedShareholderIndex];
			if (recoveredPublicKey.equals(expectedPublicKey)) {
				final ShamirShare recoveredShare = new ShamirShare(BigInteger.valueOf(corruptedShareholderIndex + 1),
						recoveredY);
				return recoveredShare;
			} else {
				throw new RuntimeException("Share decoded inconsistently, this should not happen");
			}

		} else {
			throw new IllegalStateException("Must be in States.PROCESSED_REBUTTALS");
		}
	}

}
