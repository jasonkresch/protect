/*
 * Copyright (c) IBM Corporation 2018. All Rights Reserved.
 * Project name: pross
 * This project is licensed under the MIT License, see LICENSE.
 */

package com.ibm.pross.server.shareholder.state;

import java.math.BigInteger;
import java.security.PrivateKey;
import java.util.Arrays;
import java.util.List;
import java.util.Map.Entry;
import java.util.SortedSet;
import java.util.TreeSet;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.atomic.AtomicInteger;

import com.ibm.pross.common.CommonConfiguration;
import com.ibm.pross.common.util.crypto.ecc.EcCurve;
import com.ibm.pross.common.util.crypto.ecc.EcPoint;
import com.ibm.pross.common.util.shamir.ShamirShare;
import com.ibm.pross.server.channel.AtomicBroadcastChannel;
import com.ibm.pross.server.channel.ChannelSender;
import com.ibm.pross.server.messages.Message;
import com.ibm.pross.server.messages.SemiPrivateMessage;
import com.ibm.pross.server.messages.SignedMessage;
import com.ibm.pross.server.messages.payloads.reconstruction.ReconstructionAccusations;
import com.ibm.pross.server.messages.payloads.reconstruction.ReconstructionContribution;
import com.ibm.pross.server.messages.payloads.reconstruction.ReconstructionDetectCorrupt;
import com.ibm.pross.server.messages.payloads.reconstruction.ReconstructionRebuttal;
import com.ibm.pross.server.messages.payloads.reconstruction.ReconstructionVssPublicPayload;
import com.ibm.pross.server.shareholder.Shareholder;

public class ReconstructionStateTracker {

	// Static fields
	final public static EcCurve curve = CommonConfiguration.CURVE;
	final public static BigInteger r = curve.getR();
	final public static EcPoint G = curve.getG();

	// Shareholder who is managing this state
	private final Shareholder shareholder;

	// Messages
	private final SignedMessage ourSignedDetectionMessage;
	private final ConcurrentMap<Integer, ReconstructionDetectCorrupt> receivedCorruptDetectMessages = new ConcurrentHashMap<>();
	private final SortedSet<Integer> ourDetectedCorruptions = new TreeSet<>();

	// State tracking for each share reconstruction
	private final ConcurrentMap<Integer, ReconstructShareStateTracker> reconstructionStates = new ConcurrentHashMap<>();

	// Parameters related to current time of operation
	private final long timePeriod;

	// Parameters related to threshold
	private final int threshold;
	private final int updateThreshold;
	private final int n;

	enum States {
		INITALIZED, SENT_DETECTION, RECEIVED_DETECTIONS, COUNTED_VOTES, CREATED_POLYNOMIALS, SENT_POLYNOMIALS, RECEIVED_POLYNOMIALS, VERIFIED_POLYNOMIALS, MADE_ACCUSATIONS, SENT_REBUTTALS, PROCESSED_REBUTTALS, SENT_RECONSTRUCTION_CONTRIBUTIONS, COMPLETED_REBUILD;
	}

	private volatile States currentState;

	public ReconstructionStateTracker(final Shareholder shareholder, final long timePeriod, final int threshold,
			final int updateThreshold, final int n, final ShamirShare share) {

		this.shareholder = shareholder;
		this.timePeriod = timePeriod;

		this.threshold = threshold;
		this.updateThreshold = updateThreshold;
		this.n = n;

		// Section 4.1

		// Build a single public message, to be sent as our vote of the current
		// state of the system

		// Recompute our share's public key based on our share (ensure it is
		// correct)
		final EcPoint newSharePublicKey = curve.multiply(G, share.getY());
		this.shareholder.getSharePublicKeys()[this.shareholder.getIndex()] = newSharePublicKey;

		final ReconstructionDetectCorrupt publicPayload = new ReconstructionDetectCorrupt(timePeriod,
				this.shareholder.getSharePublicKeys());

		final Message unsignedMessage = this.shareholder.createPublicMessage(publicPayload);
		this.ourSignedDetectionMessage = this.shareholder.createSignedMessage(unsignedMessage);

		this.currentState = States.INITALIZED;
	}

	public SignedMessage getOurSignedDetectionMessage() {
		return ourSignedDetectionMessage;
	}

	public synchronized void sendOurSignedDetectionMessage(final ChannelSender sender) {
		if (this.currentState.equals(States.INITALIZED)) {
			sender.broadcast(ourSignedDetectionMessage);
			this.currentState = States.SENT_DETECTION;
		} else {
			throw new IllegalStateException("Must be in States.INITIALIZED");
		}
	}

	public void saveDetectCorrupt(int sender, ReconstructionDetectCorrupt payload) {
		if (!(this.currentState.equals(States.SENT_DETECTION) || this.currentState.equals(States.INITALIZED))) {
			throw new IllegalStateException("Must be in States.SENT_DETECTION or States.INITIALIZED");
		}

		final ReconstructionDetectCorrupt previous = this.receivedCorruptDetectMessages.putIfAbsent(sender, payload);

		if (previous != null) {
			// Received duplicate message from this sender!
			System.err.println(
					"Shareholder [" + this.shareholder.getIndex() + "] received duplicate messages [" + sender + "]");
			this.getOurDetectedCorruptions().add(sender);
		}

	}

	public synchronized EcPoint[] determineCurrentSystemState() {
		if (this.currentState.equals(States.SENT_DETECTION)) {
			this.currentState = States.RECEIVED_DETECTIONS;

			// Filter all of our saved messages according to accusations
			for (Integer corrupted : this.getOurDetectedCorruptions()) {
				this.receivedCorruptDetectMessages.remove(corrupted);
			}

			// Create a map to count votes
			final ConcurrentMap<List<EcPoint>, AtomicInteger> votes = new ConcurrentHashMap<>();
			for (final ReconstructionDetectCorrupt message : this.receivedCorruptDetectMessages.values()) {
				final List<EcPoint> key = Arrays.asList(message.getSharePublicKeys());
				votes.putIfAbsent(key, new AtomicInteger(0));
				votes.get(key).incrementAndGet();
			}

			int bestVoteCount = 0;
			EcPoint[] bestState = null;
			for (final Entry<List<EcPoint>, AtomicInteger> entry : votes.entrySet()) {
				if (entry.getValue().get() > bestVoteCount) {
					bestVoteCount = entry.getValue().get();
					bestState = entry.getKey().toArray(new EcPoint[entry.getKey().size()]);
				}
			}

			this.currentState = States.COUNTED_VOTES;

			// Require majority
			if (bestVoteCount > (this.n / 2)) {
				// Update our view of the detected corruptions
				for (int i = 0; i < n; i++) {
					final ReconstructionDetectCorrupt message = this.receivedCorruptDetectMessages.get(i);
					if (message == null) {
						// We never got a response, or got multiple responses
						this.getOurDetectedCorruptions().add(i);
					} else {
						if (!Arrays.asList(bestState).equals(Arrays.asList(message.getSharePublicKeys()))) {
							// They sent a view inconsistent with majority
							this.getOurDetectedCorruptions().add(i);
						}
					}
				}

				return bestState;
			} else {
				// The system has permanently failed!
				return null;
			}

		} else {
			throw new IllegalStateException("Must be in States.SENT_DETECTION");
		}
	}

	public SortedSet<Integer> getOurDetectedCorruptions() {
		return ourDetectedCorruptions;
	}

	public synchronized void createPolynomialUpdateMessages() {
		if (this.currentState.equals(States.COUNTED_VOTES)) {
			this.currentState = States.CREATED_POLYNOMIALS;

			// Create a reconstruction state tracker for each corruption
			for (final Integer corruptedShareholderIndex : this.getOurDetectedCorruptions()) {
				final ReconstructShareStateTracker reconstructionStateTracker = new ReconstructShareStateTracker(
						shareholder, this.timePeriod, this.threshold, this.updateThreshold, this.n,
						corruptedShareholderIndex, this.ourDetectedCorruptions);
				reconstructionStates.putIfAbsent(corruptedShareholderIndex, reconstructionStateTracker);
			}
		} else {
			throw new IllegalStateException("Must be in States.COUNTED_VOTES");
		}
	}

	public synchronized void sendPolynomialUpdateMessages(final ChannelSender sender) {
		if (this.currentState.equals(States.CREATED_POLYNOMIALS)) {
			this.currentState = States.SENT_POLYNOMIALS;

			for (final ReconstructShareStateTracker reconstructShareState : this.reconstructionStates.values()) {
				// Broadcast our update message
				reconstructShareState.sendOurSignedUpdateMessage(sender);
			}
		} else {
			throw new IllegalStateException("Must be in States.CREATED_POLYNOMIALS");
		}
	}

	public void savePolynomialUpdateMessage(int sender, final SignedMessage signedMessage,
			final PrivateKey privateDecryptionKey) {
		if (this.currentState.equals(States.CREATED_POLYNOMIALS) || this.currentState.equals(States.SENT_POLYNOMIALS)) {

			final SemiPrivateMessage message = (SemiPrivateMessage) signedMessage.getMessage();
			final ReconstructionVssPublicPayload publicPayload = (ReconstructionVssPublicPayload) message
					.getPublicPayload();
			int corruptIndex = publicPayload.getCorruptShareholder();

			this.reconstructionStates.get(corruptIndex).saveVssMessage(sender, signedMessage, privateDecryptionKey);

		} else {
			throw new IllegalStateException("Must be in States.CREATED_POLYNOMIALS or States.SENT_POLYNOMIALS");
		}
	}

	public synchronized void verifyReconstructionPolynomials() {
		if (this.currentState.equals(States.SENT_POLYNOMIALS)) {
			this.currentState = States.RECEIVED_POLYNOMIALS;

			for (final ReconstructShareStateTracker reconstructShareState : this.reconstructionStates.values()) {
				// Broadcast our update message
				reconstructShareState.verifyUpdateMessages();
			}

			this.currentState = States.VERIFIED_POLYNOMIALS;

		} else {
			throw new IllegalStateException("Must be in States.SENT_POLYNOMIALS");
		}

	}

	public synchronized void makeReconstructionAccusations() {
		if (this.currentState.equals(States.VERIFIED_POLYNOMIALS)) {

			for (final ReconstructShareStateTracker reconstructShareState : this.reconstructionStates.values()) {
				// Broadcast our update message
				reconstructShareState.sendAccusations();
			}

			this.currentState = States.MADE_ACCUSATIONS;

		} else {
			throw new IllegalStateException("Must be in States.VERIFIED_POLYNOMIALS");
		}
	}

	public void saveAccusation(final int sender, final ReconstructionAccusations accusations) {

		if (!(this.currentState.equals(States.MADE_ACCUSATIONS)
				|| this.currentState.equals(States.VERIFIED_POLYNOMIALS))) {
			throw new IllegalStateException("Must be in State.VERIFIED_POLYNOMIALS or States.MADE_ACCUSATIONS");
		}

		final int corruptIndex = accusations.getCorruptShareholder();
		if (this.reconstructionStates.containsKey(corruptIndex)) {
			this.reconstructionStates.get(corruptIndex).saveAccusation(sender, accusations);
		} else {
			// Ignore
		}
	}

	public synchronized void sendReconstructionRebuttals() {
		if (this.currentState.equals(States.MADE_ACCUSATIONS)) {

			for (final ReconstructShareStateTracker reconstructShareState : this.reconstructionStates.values()) {
				// Broadcast our update message
				reconstructShareState.sendRebuttles();
			}

			this.currentState = States.SENT_REBUTTALS;

		} else {
			throw new IllegalStateException("Must be in States.MADE_ACCUSATIONS");
		}
	}

	public void saveRebuttle(final int sender, final ReconstructionRebuttal rebuttal) {

		if (!(this.currentState.equals(States.MADE_ACCUSATIONS) || this.currentState.equals(States.SENT_REBUTTALS))) {
			throw new IllegalStateException("Must be in State.SENT_REBUTTALS or States.MADE_ACCUSATIONS");
		}

		final int corruptIndex = rebuttal.getCorruptShareholder();
		if (this.reconstructionStates.containsKey(corruptIndex)) {
			this.reconstructionStates.get(corruptIndex).saveRebuttal(sender, rebuttal);
		} else {
			// Ignore
		}
	}

	public synchronized void processReconstructionRebuttals() {
		if (this.currentState.equals(States.SENT_REBUTTALS)) {

			for (final ReconstructShareStateTracker reconstructShareState : this.reconstructionStates.values()) {
				// Broadcast our update message
				reconstructShareState.processRebuttles();
			}

			this.currentState = States.PROCESSED_REBUTTALS;

		} else {
			throw new IllegalStateException("Must be in States.SENT_REBUTTALS");
		}

	}

	public synchronized void attemptCreateAndSendShareUpdate(final ShamirShare share, final PrivateKey decryptionKey) {
		if (this.currentState == States.PROCESSED_REBUTTALS) {

			for (final ReconstructShareStateTracker reconstructShareState : this.reconstructionStates.values()) {
				// Broadcast our update message
				reconstructShareState.createAndSendRebuildShareContribution(share, decryptionKey);
			}

			this.currentState = States.SENT_RECONSTRUCTION_CONTRIBUTIONS;

		} else {
			throw new IllegalStateException("Must be in States.PROCESSED_REBUTTALS");
		}

	}

	public void saveContribution(final int sender, final ReconstructionContribution reconstructionContribution) {
		if (!(this.currentState.equals(States.PROCESSED_REBUTTALS)
				|| this.currentState.equals(States.SENT_RECONSTRUCTION_CONTRIBUTIONS))) {
			throw new IllegalStateException(
					"Must be in State.PROCESSED_REBUTTALS or States.SENT_RECONSTRUCTION_CONTRIBUTIONS");
		}

		// This is for us, look up our own corruption
		final int corruptIndex = shareholder.getIndex();
		if (this.reconstructionStates.containsKey(corruptIndex)
				&& (reconstructionContribution.getUpdateTime() == this.timePeriod)) {
			this.reconstructionStates.get(corruptIndex).saveReconstructionContribution(sender,
					reconstructionContribution);
		} else {
			// Ignore
		}
	}

	public ShamirShare processReconstructionContributions(final ShamirShare existingShare) {
		if (this.currentState == States.SENT_RECONSTRUCTION_CONTRIBUTIONS) {
			this.currentState = States.COMPLETED_REBUILD;

			// This is for us, look up our own corruption
			final int corruptIndex = shareholder.getIndex();
			if (this.reconstructionStates.containsKey(corruptIndex)) {
				return this.reconstructionStates.get(corruptIndex).processReconstructionContributions();
			} else {
				// We are healthy, yay!
				return existingShare;
			}

		} else {
			throw new IllegalStateException("Must be in States.SENT_RECONSTRUCTION_CONTRIBUTIONS");
		}
	}

}
