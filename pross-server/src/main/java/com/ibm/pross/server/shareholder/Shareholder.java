/*
 * Copyright (c) IBM Corporation 2018. All Rights Reserved.
 * Project name: pross
 * This project is licensed under the MIT License, see LICENSE.
 */

package com.ibm.pross.server.shareholder;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.Collections;
import java.util.Map;
import java.util.NavigableMap;
import java.util.Set;
import java.util.TreeMap;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

import com.ibm.pross.common.CommonConfiguration;
import com.ibm.pross.common.PseudoRandomFunction;
import com.ibm.pross.common.util.crypto.EcKeyGeneration;
import com.ibm.pross.common.util.crypto.ecc.EcCurve;
import com.ibm.pross.common.util.crypto.ecc.EcPoint;
import com.ibm.pross.common.util.serialization.Serialization;
import com.ibm.pross.common.util.shamir.ShamirShare;
import com.ibm.pross.server.Administration;
import com.ibm.pross.server.Channel;
import com.ibm.pross.server.Clock;
import com.ibm.pross.server.messages.EciesEncryption;
import com.ibm.pross.server.messages.EncryptedPayload;
import com.ibm.pross.server.messages.Message;
import com.ibm.pross.server.messages.Payload;
import com.ibm.pross.server.messages.PrivateMessage;
import com.ibm.pross.server.messages.PublicMessage;
import com.ibm.pross.server.messages.SemiPrivateMessage;
import com.ibm.pross.server.messages.SignedMessage;
import com.ibm.pross.server.messages.payloads.PublicPrivatePayload;
import com.ibm.pross.server.messages.payloads.dkg.GenerationAccusations;
import com.ibm.pross.server.messages.payloads.dkg.GenerationRebuttal;
import com.ibm.pross.server.messages.payloads.reconstruction.ReconstructionAccusations;
import com.ibm.pross.server.messages.payloads.reconstruction.ReconstructionContribution;
import com.ibm.pross.server.messages.payloads.reconstruction.ReconstructionDetectCorrupt;
import com.ibm.pross.server.messages.payloads.reconstruction.ReconstructionRebuttal;
import com.ibm.pross.server.messages.payloads.refresh.RefreshAccusations;
import com.ibm.pross.server.messages.payloads.refresh.RefreshRebuttal;
import com.ibm.pross.server.messages.payloads.rekey.DynamicRekey;
import com.ibm.pross.server.shareholder.state.GenerationStateTracker;
import com.ibm.pross.server.shareholder.state.ReconstructionStateTracker;
import com.ibm.pross.server.shareholder.state.RefreshStateTracker;
import com.ibm.pross.server.shareholder.state.RekeyingStateTracker;

public class Shareholder implements PseudoRandomFunction {

	// Static fields
	final public static EcCurve curve = CommonConfiguration.CURVE;
	final public static BigInteger r = curve.getR();
	final public static EcPoint G = curve.getG();

	// Public key used to send us encrypted messages
	// Private key used to decrypt messages that we receive
	protected volatile KeyPair decryptionKeyPair;

	// Public key used to verify our signed messages
	// Private key used to sign messages we transmit
	protected volatile KeyPair signingKeyPair;

	// Share this shareholder is responsible for maintaining
	protected volatile ShamirShare share;

	// Implements synchronous channel for communicating messages among
	// shareholders
	protected final Channel channel;

	// Single DKG state
	protected volatile GenerationStateTracker generationState;

	// Clock and state that is tracked for each time period
	protected final Clock clock;
	protected final ConcurrentMap<Long, RefreshStateTracker> refreshStates = new ConcurrentHashMap<>();
	protected final ConcurrentMap<Long, ReconstructionStateTracker> reconstructionStates = new ConcurrentHashMap<>();
	protected final ConcurrentMap<Long, RekeyingStateTracker> rekeyingStates = new ConcurrentHashMap<>();

	// Public parameters for verification and secure communication
	protected volatile PublicKey[] othersEncryptionPublicKeys;
	protected volatile PublicKey[] othersVerifyingPublicKeys;

	// Parameters of the secret sharing
	protected final int index;
	protected final Administration.Configuration configuration;

	// Public key of overall shared secret
	protected volatile EcPoint secretPublicKey;
	protected volatile EcPoint[] sharePublicKeys;

	public Shareholder(final Channel channel, final Clock clock, final int index,
			final Administration.Configuration configuration) {

		// Private values
		this.decryptionKeyPair = EcKeyGeneration.generateKeyPair();
		this.signingKeyPair = EcKeyGeneration.generateKeyPair();
		this.share = share;

		// Secret sharing parameters
		this.index = index;
		this.configuration = configuration;

		// Shared configuration
		this.channel = channel;
		this.clock = clock;

		// Subscribe to receive messages
		this.channel.register(this);
	}

	public int getIndex() {
		return index;
	}

	/**
	 * Get current public keys defined by the Administration's configuration
	 */
	public void updateKeysFromConfiguration() {
		this.othersEncryptionPublicKeys = this.configuration.getEncryptionPublicKeys().toArray(new PublicKey[0]);
		this.othersVerifyingPublicKeys = this.configuration.getVerifyingPublicKeys().toArray(new PublicKey[0]);
	}

	public PublicKey getEncryptionPublicKey() {
		return this.decryptionKeyPair.getPublic();
	}

	public PublicKey getVerifyingPublicKey() {
		return this.signingKeyPair.getPublic();
	}

	public PublicKey getOtherShareholderEncryptionPublicKey(int shareholderIndex) {
		return this.othersEncryptionPublicKeys[shareholderIndex];
	}

	public PublicKey getOtherShareholderVerificationPublicKey(int shareholderIndex) {
		return this.othersVerifyingPublicKeys[shareholderIndex];
	}

	/**
	 * Processes a message from a channel we have registered with
	 * 
	 * @param message
	 */
	public void receiveSerializedMessage(final byte[] serializedMessage) {
		SignedMessage signedMessage = (SignedMessage) Serialization.deserialize(serializedMessage);
		this.process(signedMessage);
	}

	/**
	 * Process a signed message received from a channel we have registered with
	 * 
	 * @param message
	 */
	protected void process(final SignedMessage signedMessage) {

		// Get the message
		final Message message = signedMessage.getMessage();

		// Determine the recipient
		if (!message.isRecipient(this.index)) {
			return; // Not for us, ignore it
		}

		// Determine the sender
		final int sender = message.getSenderIndex();
		final PublicKey senderVerificationPublicKey = getOtherShareholderVerificationPublicKey(sender);

		// Verify the message signature using sender's public key
		if (!signedMessage.isSignatureValid(senderVerificationPublicKey)) {
			System.out.println("Shareholder [" + this.index + "] received message from shareholder [" + sender
					+ "] with invalid signature!");
			return; // Not valid, ignore it
		}

		// Get the content of the message
		final Payload payload;
		if (message instanceof PublicMessage) {
			// We received a public message, decrypt it
			payload = ((PublicMessage) message).getPayload();
		} else if (message instanceof PrivateMessage) {
			// We received a private message, decrypt it
			final EncryptedPayload encryptedContent = ((PrivateMessage) message).getEncryptedPayload();
			payload = EciesEncryption.decryptPayload(encryptedContent, this.decryptionKeyPair.getPrivate());
		} else if (message instanceof SemiPrivateMessage) {
			// We received a semi private message, decrypt it
			final EncryptedPayload encryptedContent = ((SemiPrivateMessage) message).getEncryptedPayload(this.index);
			final Payload privatePayload = EciesEncryption.decryptPayload(encryptedContent,
					this.decryptionKeyPair.getPrivate());
			final Payload publicPayload = ((SemiPrivateMessage) message).getPublicPayload();
			payload = new PublicPrivatePayload(publicPayload, privatePayload);
		} else {
			System.out.println("Received unknown message type!");
			return;
		}

		System.out.println("Shareholder [" + this.index + "] received message from shareholder [" + sender
				+ "] to be processed. Type = " + payload);

		// Get current time
		final long currentTime = this.clock.getTime();

		// Access any previously created state trackers for this time
		final RefreshStateTracker refreshState = this.refreshStates.get(currentTime);
		final ReconstructionStateTracker reconstructionState = this.reconstructionStates.get(currentTime);
		final RekeyingStateTracker rekeyState = this.rekeyingStates.get(currentTime);

		// Process the content according to its type
		switch (payload.getOpcode()) {

		/** Generation **/
		case DKG_VSS:
			// Save updates to be processed and verified
			this.generationState.saveVssMessage(sender, signedMessage, this.decryptionKeyPair.getPrivate());
			break;
		case DKG_ACCUSATIONS:
			// Save accusations to be processed and verified
			this.generationState.saveAccusation(sender, (GenerationAccusations) payload);
			break;
		case DKG_REBUTTAL:
			// Save accusations to be processed and verified
			this.generationState.saveRebuttle(sender, (GenerationRebuttal) payload);
			break;

		/** Rekey **/
		case DYNAMIC_REKEY:
			rekeyState.saveKeyUpdate(sender, (DynamicRekey) payload);
			break;

		/** Reconstruction **/
		case RECONSTRUCTION_DETECT_CORRUPT:
			// Save accusations to be processed and verified
			reconstructionState.saveDetectCorrupt(sender, (ReconstructionDetectCorrupt) payload);
			break;
		case RECONSTRUCTION_VSS:
			// Save polynomial updates to be processed and verified
			reconstructionState.savePolynomialUpdateMessage(sender, signedMessage, this.decryptionKeyPair.getPrivate());
			break;
		case RECONSTRUCTION_ACCUSATIONS:
			reconstructionState.saveAccusation(sender, (ReconstructionAccusations) payload);
			break;
		case RECONSTRUCTION_REBUTTAL:
			// Save accusations to be processed and verified
			reconstructionState.saveRebuttle(sender, (ReconstructionRebuttal) payload);
			break;
		case RECONSTRUCTION_CONTRIBUTION:
			reconstructionState.saveContribution(sender, (ReconstructionContribution) payload);
			break;

		/** Refresh **/
		case REFRESH_VSS:
			// Save updates to be processed and verified
			refreshState.saveVssMessage(sender, signedMessage, this.decryptionKeyPair.getPrivate());
			break;
		case REFRESH_ACCUSATIONS:
			// Save accusations to be processed and verified
			refreshState.saveAccusation(sender, (RefreshAccusations) payload);
			break;
		case REFRESH_REBUTTAL:
			// Save accusations to be processed and verified
			refreshState.saveRebuttle(sender, (RefreshRebuttal) payload);
			break;

		default:
			throw new IllegalArgumentException("Unknown message type");
		}
	}

	/**
	 * Creates a secure, encrypted and signed, message to the designated
	 * recipients over the broadcast channel
	 * 
	 * @param publicPayload
	 *            The public part of the payload visible to every recipient
	 * @param privatePayloads
	 *            A mapping of recipient indices to their private payloads which
	 *            will be encrypted
	 */
	public SemiPrivateMessage createSemiPrivateMessage(final Payload publicPayload,
			final Map<Integer, Payload> privatePayloads) {

		// Create map for storing encrypted payloads
		final NavigableMap<Integer, EncryptedPayload> encryptedPayloads = new TreeMap<>();
		for (Integer recipientIndex : privatePayloads.keySet()) {
			// Use recipient public key to encrypt each private payload
			final PublicKey recipientPublicKey = getOtherShareholderEncryptionPublicKey(recipientIndex);

			// Create an encrypted payload from this private payload
			EncryptedPayload encryptedPayload = EciesEncryption.encrypt(privatePayloads.get(recipientIndex),
					recipientPublicKey);

			// Store it in the new map
			encryptedPayloads.put(recipientIndex, encryptedPayload);
		}

		// Create a semi-private message
		final SemiPrivateMessage message = new SemiPrivateMessage(this.index, publicPayload, encryptedPayloads);
		return message;
	}

	public void sendSemiPrivateMessage(final Payload publicPayload, final Map<Integer, Payload> privatePayloads) {
		final SemiPrivateMessage unsignedMessage = createSemiPrivateMessage(publicPayload, privatePayloads);
		sendSignedMessage(unsignedMessage);
	}

	/**
	 * Creates a secure, encrypted and signed, message to the designated
	 * recipient over the broadcast channel
	 * 
	 * @param recipient
	 * @param payload
	 */
	public PrivateMessage createPrivateMessage(final int recipientIndex, final Payload payload) {
		// Use recipient public key to encrypt the message
		final PublicKey publicKey = getOtherShareholderEncryptionPublicKey(recipientIndex);
		final PrivateMessage message = new PrivateMessage(this.index, recipientIndex, publicKey, payload);
		return message;
	}

	public void sendPrivateMessage(final int recipientIndex, final Payload payload) {
		final PrivateMessage unsignedMessage = createPrivateMessage(recipientIndex, payload);
		sendSignedMessage(unsignedMessage);
	}

	/**
	 * Creates an unencrypted, message that is received by everyone
	 * 
	 * @param payload
	 */
	public PublicMessage createPublicMessage(final Payload payload) {
		// Create a public message
		final PublicMessage message = new PublicMessage(this.index, payload);
		return message;
	}

	public void sendPublicMessage(final Payload payload) {
		final PublicMessage unsignedMessage = createPublicMessage(payload);
		sendSignedMessage(unsignedMessage);
	}

	/**
	 * Creates a signed message ready for the broadcast channel
	 * 
	 * @param unsignedMessage
	 */
	public SignedMessage createSignedMessage(final Message unsignedMessage) {
		// Use our private key to sign the message
		final SignedMessage signedMessage = new SignedMessage(unsignedMessage, this.signingKeyPair.getPrivate());
		return signedMessage;
	}

	public void sendSignedMessage(final Message unsignedMessage) {
		final SignedMessage signedMessage = createSignedMessage(unsignedMessage);
		this.send(signedMessage);
	}

	/**
	 * Sends a signed message to the broadcast channel
	 * 
	 * @param message
	 */
	public void send(final SignedMessage message) {
		// Send to broadcast channel
		this.channel.broadcast(message);
	}

	/////////////////////////////////////////////////////////////////////////////
	// Coordinator-driven operations
	/////////////////////////////////////////////////////////////////////////////

	/************** Refresh Functions ****************/

	// Step 1 of refresh
	public void generateShareUpdateMessages() {

		// Create new state to track this operation's phases
		final long currentTime = this.clock.getTime();
		final RefreshStateTracker stateTracker = new RefreshStateTracker(this, currentTime,
				configuration.getThreshold(), configuration.getUpdateThreshold(), configuration.getN());
		this.refreshStates.putIfAbsent(currentTime, stateTracker);
	}

	// Step 2 of refresh
	public void sendShareUpdateMessages() {

		// Get existing state that track this operation's phases
		final long currentTime = this.clock.getTime();
		final RefreshStateTracker stateTracker = this.refreshStates.get(currentTime);

		// Broadcast our update message
		stateTracker.sendOurSignedUpdateMessage(this.channel);
	}

	// Step 3 of refresh
	public void verifyUpdateMessages() {
		// Get existing state that track this operation's phases
		final long currentTime = this.clock.getTime();
		final RefreshStateTracker stateTracker = this.refreshStates.get(currentTime);

		// Broadcast our update message
		stateTracker.verifyUpdateMessages();
	}

	// Step 4 of refresh
	public void makeAccusations() {
		// Get existing state that track this operation's phases
		final long currentTime = this.clock.getTime();
		final RefreshStateTracker stateTracker = this.refreshStates.get(currentTime);

		// Broadcast our update message
		stateTracker.sendAccusations();

	}

	// Step 5 of refresh
	public void sendRebuttals() {
		// Get existing state that track this operation's phases
		final long currentTime = this.clock.getTime();
		final RefreshStateTracker stateTracker = this.refreshStates.get(currentTime);

		// Broadcast our update message
		stateTracker.sendRebuttals();
	}

	// Step 6 of refresh
	public void processRebuttles() {
		// Get existing state that track this operation's phases
		final long currentTime = this.clock.getTime();
		final RefreshStateTracker stateTracker = this.refreshStates.get(currentTime);

		// Broadcast our update message
		stateTracker.processRebuttals();
	}

	// Step 7 of refresh
	public boolean attemptShareUpdate() {
		// Get existing state that track this operation's phases
		final long currentTime = this.clock.getTime();
		final RefreshStateTracker stateTracker = this.refreshStates.get(currentTime);

		// Broadcast our update message
		final ShamirShare updatedShare = stateTracker.attemptShareUpdate(this.share,
				this.decryptionKeyPair.getPrivate());

		if (updatedShare != null) {
			this.share = updatedShare;
			stateTracker.updateSharePublicKeys(this.sharePublicKeys);
			return true;
		} else {
			return false;
		}

	}

	// Step 8 of refresh
	public Set<Integer> getCorruptionReport() {
		// Get existing state that track this operation's phases
		final long currentTime = this.clock.getTime();
		final RefreshStateTracker stateTracker = this.refreshStates.get(currentTime);

		// Broadcast our update message
		return Collections.unmodifiableSet(stateTracker.getOurAccusations());
	}

	/************** Detection Functions ****************/

	// Step 1 of corruption detection
	public void generateDetectCorruptShareMessage() {

		// Create new state to track this operation's phases
		final long currentTime = this.clock.getTime();
		final ReconstructionStateTracker stateTracker = new ReconstructionStateTracker(this, currentTime,
				configuration.getThreshold(), configuration.getUpdateThreshold(), configuration.getN(), this.share);
		this.reconstructionStates.putIfAbsent(currentTime, stateTracker);
	}

	// Step 2 of corruption detection
	public void sendDetectCorruptMessages() {

		// Get existing state that track this operation's phases
		final long currentTime = this.clock.getTime();
		final ReconstructionStateTracker stateTracker = this.reconstructionStates.get(currentTime);

		// Broadcast our update message
		stateTracker.sendOurSignedDetectionMessage(this.channel);
	}

	// Step 3 of corruption detection AND Step 1 of reconstruction
	public Set<Integer> determineCorruptShareholders() throws Exception {
		// Get existing state that track this operation's phases
		final long currentTime = this.clock.getTime();
		final ReconstructionStateTracker stateTracker = this.reconstructionStates.get(currentTime);

		// Determine current state from previously saved votes
		final EcPoint[] currentState = stateTracker.determineCurrentSystemState();

		if (currentState == null) {
			throw new Exception("The system has been corrupted!");
		} else {
			if (stateTracker.getOurDetectedCorruptions().contains(this.getIndex())) {
				// We need to be rebuilt
				// Update our view to line up with majority
				this.sharePublicKeys = currentState;
			}
			return stateTracker.getOurDetectedCorruptions();
		}

	}

	/************** Reconstruction Functions ****************/

	// Step 1 of reconstruction
	public void createPolynomialUpdateMessages() {

		// Get existing state that track this operation's phases
		final long currentTime = this.clock.getTime();
		final ReconstructionStateTracker stateTracker = this.reconstructionStates.get(currentTime);

		// Broadcast our update message
		stateTracker.createPolynomialUpdateMessages();
	}

	// Step 2 of reconstruction
	public void sendReconstructionPolynomials() {
		// Get existing state that track this operation's phases
		final long currentTime = this.clock.getTime();
		final ReconstructionStateTracker stateTracker = this.reconstructionStates.get(currentTime);

		stateTracker.sendPolynomialUpdateMessages(this.channel);
	}

	// Step 3 of refresh
	public void verifyReconstructionPolynomials() {
		// Get existing state that track this operation's phases
		final long currentTime = this.clock.getTime();
		final ReconstructionStateTracker stateTracker = this.reconstructionStates.get(currentTime);

		stateTracker.verifyReconstructionPolynomials();
	}

	// step 4 of refresh
	public void makeReconstructionAccusations() {
		// Get existing state that track this operation's phases
		final long currentTime = this.clock.getTime();
		final ReconstructionStateTracker stateTracker = this.reconstructionStates.get(currentTime);

		stateTracker.makeReconstructionAccusations();
	}

	// step 5 of refresh
	public void sendReconstructionRebuttals() {
		// Get existing state that track this operation's phases
		final long currentTime = this.clock.getTime();
		final ReconstructionStateTracker stateTracker = this.reconstructionStates.get(currentTime);

		stateTracker.sendReconstructionRebuttals();
	}

	// step 6 of refresh
	public void processReconstructionRebuttals() {
		// Get existing state that track this operation's phases
		final long currentTime = this.clock.getTime();
		final ReconstructionStateTracker stateTracker = this.reconstructionStates.get(currentTime);

		stateTracker.processReconstructionRebuttals();
	}

	// step 7 of refresh
	public void attemptCreateAndSendShareUpdate() {
		// Get existing state that track this operation's phases
		final long currentTime = this.clock.getTime();
		final ReconstructionStateTracker stateTracker = this.reconstructionStates.get(currentTime);

		stateTracker.attemptCreateAndSendShareUpdate(this.share, this.decryptionKeyPair.getPrivate());
	}

	// step 8 of refresh
	public boolean processContributions() {
		// Get existing state that track this operation's phases
		final long currentTime = this.clock.getTime();
		final ReconstructionStateTracker stateTracker = this.reconstructionStates.get(currentTime);

		final ShamirShare recoveredShare = stateTracker.processReconstructionContributions(this.share);
		if (recoveredShare != null) {
			this.share = recoveredShare;
			return true;
		} else {
			return false;
		}
	}

	/************** Key Update Functions ****************/

	// Step 1 of rekey
	public void generateNewKeys() {

		// Create new state to track this operation's phases
		final long currentTime = this.clock.getTime();
		final RekeyingStateTracker stateTracker = new RekeyingStateTracker(currentTime, this, configuration.getN());

		this.rekeyingStates.putIfAbsent(currentTime, stateTracker);
	}

	// Step 2 of rekey
	public void sendRekeyPayload() {

		// Get existing state that track this operation's phases
		final long currentTime = this.clock.getTime();
		final RekeyingStateTracker stateTracker = this.rekeyingStates.get(currentTime);

		// Broadcast our update message
		stateTracker.sendRekeyMessage();
	}

	// Step 3 of rekey
	public Set<Integer> performKeyUpdate() {
		// Get existing state that track this operation's phases
		final long currentTime = this.clock.getTime();
		final RekeyingStateTracker stateTracker = this.rekeyingStates.get(currentTime);

		// Determine corrupt shareholders
		stateTracker.determineMalfunctioningShareholders();

		// Update public keys
		stateTracker.updateKeys(othersVerifyingPublicKeys, othersEncryptionPublicKeys);

		// Update our key pairs
		this.decryptionKeyPair = stateTracker.getDecryptionKeyPair();
		this.signingKeyPair = stateTracker.getSigningKeyPair();

		// Return malfunctioning shareholders
		return stateTracker.getMalfunctioningShareholders();
	}

	/************** Distributed Key Generation Functions ****************/

	// Step 1 of generation
	public synchronized void generateShareGenerationMessages() {

		if (this.generationState == null) {
			// State tracking for one-time distributed key generation
			this.generationState = new GenerationStateTracker(this, configuration.getThreshold(),
					configuration.getUpdateThreshold(), configuration.getN());
		}

	}

	// Step 2 of generation
	public void sendShareGenerationMessages() {

		// Broadcast our update message
		this.generationState.sendOurSignedUpdateMessage(this.channel);
	}

	// Step 3 of generation
	public void verifyGenerationMessages() {

		// Determine which nodes sent us valid messages
		this.generationState.verifyUpdateMessages();
	}

	// Step 4 of generation
	public void makeGenerationAccusations() {

		// Broadcast our update message
		this.generationState.sendAccusations();

	}

	// Step 5 of generation
	public void sendGenerationRebuttals() {

		// Broadcast our update message
		this.generationState.sendRebuttals();
	}

	// Step 6 of generation
	public void processGenerationRebuttles() {

		// Broadcast our update message
		this.generationState.processRebuttals();
	}

	// Step 7 of generation
	public boolean attemptShareGeneration() {

		// Get our share
		final ShamirShare generatedShare = this.generationState
				.attemptShareGeneration(this.decryptionKeyPair.getPrivate());

		if (generatedShare != null) {

			// Set our share
			this.share = generatedShare;

			// Compute share public keys
			this.sharePublicKeys = new EcPoint[this.configuration.getN()];
			this.generationState.computeSharePublicKeys(this.sharePublicKeys);

			// Get public key for the overall secret
			this.secretPublicKey = this.generationState.getSecretPublicKey();

			return true;
		} else {
			return false;
		}

	}

	// Step 8 of generation
	public Set<Integer> getGenerationCorruptionReport() {

		// Get our accusation list
		return Collections.unmodifiableSet(this.generationState.getOurAccusations());
	}

	/////////////////////////////////////////////////////////////////////////////
	// Client-driven Derivation operations
	/////////////////////////////////////////////////////////////////////////////

	/**
	 * Computes server-side operation of OPRF
	 * 
	 * May be used as part of a T-OPRF by combining results and interpolating
	 * polynomial at y=0 (the value of the thresholdized secret)
	 * 
	 * @param blindedPoint
	 * @return
	 */
	@Override
	public EcPoint derive(final EcPoint input) {
		return curve.multiply(input, this.share.getY());
	}

	/**
	 * Returns the public key corresponding to the OPRF key used in derivation
	 */
	@Override
	public EcPoint getPublicKey() {
		return curve.multiply(G, this.share.getY());
	}

	public EcPoint getSecretPublicKey() {
		return this.secretPublicKey;
	}

	public EcPoint[] getSharePublicKeys() {
		return this.sharePublicKeys;
	}

}
