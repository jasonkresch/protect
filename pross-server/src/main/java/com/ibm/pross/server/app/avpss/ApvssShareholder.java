package com.ibm.pross.server.app.avpss;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Map.Entry;
import java.util.SortedMap;
import java.util.SortedSet;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

import com.ibm.pross.common.CommonConfiguration;
import com.ibm.pross.common.DerivationResult;
import com.ibm.pross.common.util.crypto.ecc.EcCurve;
import com.ibm.pross.common.util.crypto.ecc.EcPoint;
import com.ibm.pross.common.util.crypto.paillier.PaillierPrivateKey;
import com.ibm.pross.common.util.crypto.paillier.PaillierPublicKey;
import com.ibm.pross.common.util.crypto.zkp.splitting.ZeroKnowledgeProof;
import com.ibm.pross.common.util.crypto.zkp.splitting.ZeroKnowledgeProver;
import com.ibm.pross.common.util.pvss.PublicSharing;
import com.ibm.pross.common.util.pvss.PublicSharingGenerator;
import com.ibm.pross.common.util.shamir.Polynomials;
import com.ibm.pross.common.util.shamir.ShamirShare;
import com.ibm.pross.server.app.avpss.channel.FifoAtomicBroadcastChannel;
import com.ibm.pross.server.app.avpss.exceptions.DuplicateMessageReceivedException;
import com.ibm.pross.server.app.avpss.exceptions.ErrorConditionException;
import com.ibm.pross.server.app.avpss.exceptions.InconsistentShareException;
import com.ibm.pross.server.app.avpss.exceptions.InvalidCiphertextException;
import com.ibm.pross.server.app.avpss.exceptions.InvalidZeroKnowledgeProofException;
import com.ibm.pross.server.app.avpss.exceptions.StateViolationException;
import com.ibm.pross.server.app.avpss.exceptions.UnrecognizedMessageTypeException;
import com.ibm.pross.server.messages.Message;
import com.ibm.pross.server.messages.Payload.OpCode;
import com.ibm.pross.server.messages.PublicMessage;

import bftsmart.reconfiguration.util.sharedconfig.KeyLoader;

public class ApvssShareholder {

	enum SharingType {
		PEDERSEN_DKG, FELDMAN_DKG, STORED;
	}

	// Group Constants
	public static final EcCurve curve = CommonConfiguration.CURVE;
	public static final EcPoint g = CommonConfiguration.g;
	public static final EcPoint h = CommonConfiguration.h;

	// The set of peer shareholder's keys
	private final KeyLoader keyLoader;

	// Error log (useful for testing and for identifying problem shareholders)
	protected final AlertLog alertLog = new AlertLog();

	// Channel-related variables
	private final FifoAtomicBroadcastChannel channel;
	private final AtomicInteger currentMessageId = new AtomicInteger(0);

	// Our message processing thread
	private final Thread messageProcessingThread;
	private final AtomicBoolean stopped = new AtomicBoolean(true);

	/********************** Misc Info ******************************/
	// The unique name for this secret
	private final String secretName;

	// The current version of this secret
	private final AtomicInteger epochNumber = new AtomicInteger(0);

	// Create date of this secret
	private volatile Date creationTime;

	// Time of last epoch change
	private volatile Date lastEpochChange;

	// How the secret was established
	private volatile SharingType type;

	// Who stored the secret (if type = Stored)
	private volatile int creatorId;
	/*****************************************************************/

	// The index of this shareholder (ourself) (one is the base index)
	// This shareholder will hold the share at f(index)
	private final int index;

	// The number of shareholders
	private final int n;

	// The recovery threshold of the secret
	private final int k;

	// The maximum number of failures
	private final int f;

	// Tracks if we have sent our public sharing
	private final AtomicBoolean broadcastSharing = new AtomicBoolean(false);

	// Received public sharings
	protected final PublicSharing[] receivedSharings;

	// Our verification vector
	private final AtomicInteger successCount = new AtomicInteger(0);

	// Qualified shareholders
	private volatile SortedMap<Integer, PublicSharing> qualifiedSharings;
	private volatile boolean isQualSetDefined = false;

	// Constructed Shares (x_i)
	private volatile ShamirShare share1;
	private volatile ShamirShare share2;

	// Pedersen commitments to the co-efficients of the combined polynomial
	private volatile EcPoint[] pedersenCommitments;

	// Public Values to verify consistency of sharing
	protected final ZeroKnowledgeProof[] receivedProofs;
	private final SortedMap<Integer, EcPoint> qualifiedProofs;
	private final EcPoint[] sharePublicKeys; // g^s_i for i = 0 to n (inclusive)
	private EcPoint[] feldmanValues; // g^a_i for i = 0 to k-1 (inclusive)

	// Used to misbehave
	private final boolean sendValidCommitments;

	// Used to time operation
	private volatile long startTime;

	public ApvssShareholder(final String secretName, final KeyLoader keyLoader, final FifoAtomicBroadcastChannel channel, final int index,
			final int n, final int k, final int f) {
		this(secretName, keyLoader, channel, index, n, k, f, true);
	}

	public ApvssShareholder(final String secretName, final KeyLoader keyLoader, final FifoAtomicBroadcastChannel channel, final int index,
			final int n, final int k, final int f, final boolean sendValidCommitments) {

		this.secretName = secretName;
		
		this.sendValidCommitments = sendValidCommitments;

		/** Values unique to ourselves **/
		this.index = index;

		/** Public shared configuration parameters **/
		this.keyLoader = keyLoader;
		this.channel = channel;
		this.n = n;
		this.k = k; // (t + 1) == reconstruction threshold
		this.f = f; // t_S = maximum safety failures

		/** Variables to track sharing **/
		this.receivedSharings = new PublicSharing[n];
		this.qualifiedSharings = new TreeMap<>();

		/** Variables to track splitting proofs **/
		this.receivedProofs = new ZeroKnowledgeProof[n];
		this.qualifiedProofs = new TreeMap<>();
		this.sharePublicKeys = new EcPoint[n + 1]; // position 0 = g^s
		this.feldmanValues = new EcPoint[k];

		this.messageProcessingThread = createMessageProcessingThread(this.channel);
	}

	public Thread createMessageProcessingThread(final FifoAtomicBroadcastChannel channel) {

		return new Thread(new Runnable() {

			@Override
			public void run() {
				while (!ApvssShareholder.this.stopped.get()) {

					while (channel.getMessageCount() > currentMessageId.get()) {
						messageIsAvailable();
					}

					try {
						synchronized (channel) {
							channel.wait(1000);
						}
					} catch (InterruptedException e) {
						// Ignore
					}
				}
			}
		}, "Shareholder-Thread-" + this.index);
	}

	/**
	 * A message is available on the queue, get it and deliver it for processing
	 */
	private synchronized void messageIsAvailable() {
		int messageId = this.currentMessageId.getAndIncrement();
		final Message message = this.channel.getMessage(messageId);
		
		// Deliver only if this message is relevant for the given epoch and secret
		final String channelName = (this.epochNumber + "-" + this.secretName);
		if (message.isRecipient(channelName)) {
			// System.out.println("DKG app processing message #" + messageId);
			deliver(message);
		}
	}

	/**
	 * Deliver a message received on the FIFO-AB channel to the correct method
	 * 
	 * If any error condition occurs, an entry will be added to the alert log
	 * 
	 * @param message
	 */
	private synchronized void deliver(final Message message) {

		if (message instanceof PublicMessage) {

			final OpCode opcode = ((PublicMessage) message).getPayload().getOpcode();

			try {
				switch (opcode) {
				case PS:
					deliverPublicSharing((PublicMessage) message);
					break;
				case ZK:
					deliverProofMessage((PublicMessage) message);
					break;
				default:
					throw new UnrecognizedMessageTypeException();
				}
			} catch (final ErrorConditionException e) {
				this.alertLog.reportError(this.index, message.getSenderIndex(), e.getErrorCondition());
			}

		}
	}

	public void start(boolean sendContributions) {
		if (this.stopped.compareAndSet(true, false)) {

			if (sendContributions) {
				// First broadcast our commitment and share contributions to the channel
				broadcastPublicSharing();
			}

			// Start the shareholder (await and process messages)
			this.messageProcessingThread.start();
		}
	}

	public void stop() {

		if (this.stopped.compareAndSet(false, true)) {

			// Wake the sleeping threads
			synchronized (this.channel) {
				this.channel.notifyAll();
			}

			try {
				this.messageProcessingThread.join();
			} catch (InterruptedException e) {
				// Interrupted
			}
		}
	}

	/**
	 * Send out initial message containing our Public Sharing (privately encrypted
	 * shares to each peer shareholder, proofs of correctness and our Pedersen
	 * commitments. This will start the DKG protocol based on APVSS, and it will be
	 * driven to completion.
	 */
	public boolean broadcastPublicSharing() {

		if (this.broadcastSharing.compareAndSet(false, true)) {

			System.out.println("Starting DKG operation!");
			this.startTime = System.nanoTime();

			// Get shareholder public encryption keys
			final PaillierPublicKey[] publicKeys = new PaillierPublicKey[n];
			for (int i = 1; i <= n; i++) {
				publicKeys[i - 1] = (PaillierPublicKey) this.keyLoader.getEncryptionKey(i);
			}

			// Create Public Sharing of a random secret
			final PublicSharingGenerator generator = new PublicSharingGenerator(this.n, this.k);
			final PublicSharing publicSharing = generator.shareRandomSecret(publicKeys);

			// Create a semi-private message
			final PublicSharingPayload payload = new PublicSharingPayload(publicSharing);
			final String channelName = (this.epochNumber + "-" + this.secretName);
			final Message publicSharingMessage = new PublicMessage(channelName, this.index, payload);
			this.channel.send(publicSharingMessage);

			return true;
		} else {
			return false; // Already started
		}
	}

	/**
	 * Process received PublicSharing and update qual set
	 * 
	 * @param message
	 * @throws DuplicateMessageReceivedException
	 * @throws InvalidCiphertextException
	 * @throws InconsistentShareException
	 */
	protected synchronized void deliverPublicSharing(final PublicMessage message)
			throws DuplicateMessageReceivedException, InvalidCiphertextException, InconsistentShareException {

		// A DKG is starting, broadcast sharing if we have not already done so
		if (!broadcastSharing.get()) {
			broadcastPublicSharing();
		}

		// Check if we've seen one of these already
		final int senderIndex = message.getSenderIndex();
		if (this.receivedSharings[senderIndex - 1] != null) {
			throw new DuplicateMessageReceivedException("duplicate share contribution");
		}

		// Extract the payload
		final PublicSharing publicSharing = (PublicSharing) message.getPayload().getData();

		// Save it
		this.receivedSharings[senderIndex - 1] = publicSharing;

		// Ensure sharing matches our n and t
		if (publicSharing.getNumShares() != this.n) {
			throw new InconsistentShareException("incorrect n");
		}
		if (publicSharing.getThreshold() != this.k) {
			throw new InconsistentShareException("incorrect k");
		}

		// Get shareholder public encryption keys
		final PaillierPublicKey[] shareholderKeys = new PaillierPublicKey[n];
		for (int i = 1; i <= n; i++) {
			shareholderKeys[i - 1] = (PaillierPublicKey) this.keyLoader.getEncryptionKey(i);
		}

		// Verify the shares are correct
		if (!publicSharing.verifyAllShares(shareholderKeys)) {
			throw new InvalidCiphertextException("Public Sharing was not valid");
		}

		// It is valid, increment success count
		final int successes = this.successCount.incrementAndGet();
		if (successes <= this.f + 1) {
			// We are still building the qual set, add it
			qualifiedSharings.put(senderIndex, publicSharing);
		}

		// FIXME: Replace f with t_S
		if (successes == (this.f + 1)) {

			// We have reached a threshold to proceed to next phase
			assembleCombinedShare();
		}
	}

	/**
	 * Complete the DKG by combining all the PVSSs in Qual
	 */
	private synchronized void assembleCombinedShare() {

		// Start counters at zero
		BigInteger share1Y = BigInteger.ZERO;
		BigInteger share2Y = BigInteger.ZERO;
		EcPoint[] combinedPedersenCommitments = new EcPoint[this.k];
		for (int i = 0; i < this.k; i++) {
			combinedPedersenCommitments[i] = EcPoint.pointAtInfinity;
		}

		// Use our decryption key to access our shares
		final PaillierPrivateKey decryptionKey = (PaillierPrivateKey) this.keyLoader.getDecryptionKey();

		// Iterate over every public sharing in qual
		for (final PublicSharing sharing : this.qualifiedSharings.values()) {
			// Decrypt our shares
			final ShamirShare share1 = sharing.accessShare1(index - 1, decryptionKey);
			final ShamirShare share2 = sharing.accessShare2(index - 1, decryptionKey);

			// Get the commitments
			final EcPoint[] commitments = sharing.getPedersenCommitments();

			// Add the shares to our running sum
			share1Y = share1Y.add(share1.getY()).mod(curve.getR());
			share2Y = share2Y.add(share2.getY()).mod(curve.getR());

			// Add Pedersen commitments to our running sum
			for (int i = 0; i < this.k; i++) {
				combinedPedersenCommitments[i] = curve.addPoints(combinedPedersenCommitments[i], commitments[i]);
			}

			// TODO: Check that no longer need to do this because of the proof already
			// performed?
			// verifyShareConsistency(this.index, share1, share2, commitments);
		}

		// We have our shares
		this.share1 = new ShamirShare(BigInteger.valueOf(this.index), share1Y);
		this.share2 = new ShamirShare(BigInteger.valueOf(this.index), share2Y);

		// We have our Pedersen commitments
		this.pedersenCommitments = combinedPedersenCommitments;

		// Broadcast ZKP of a splitting
		broadcastZkp();

		this.isQualSetDefined = true;

		final long shareEnd = System.nanoTime();
		System.out.println("Time to establish share:             "
				+ (((double) (shareEnd - startTime)) / 1_000_000_000.0) + " seconds");
	}

	/**
	 * Broadcast a ZKP of our shares From these, we can interpolate all the share
	 * public keys
	 */
	private void broadcastZkp() {

		// S = g^s_i
		// R = h^r_i
		final BigInteger s = this.share1.getY();
		final BigInteger r = this.share2.getY();

		// Prove: g^s_i * h^r_i = S (Pedersen commitment)
		final ZeroKnowledgeProof proof;
		if (this.sendValidCommitments) {
			proof = ZeroKnowledgeProver.createProof(s, r);
		} else {
			// Simulate malfunction
			proof = ZeroKnowledgeProver.createProof(s, r.add(BigInteger.ONE));
		}

		// Send message out
		final ZkpPayload payload = new ZkpPayload(proof);
		final String channelName = (this.epochNumber + "-" + this.secretName);
		this.channel.send(new PublicMessage(channelName, this.index, payload));
	}

	/**
	 * Process a proof sent by another shareholder. These will be used to determine
	 * the public key of the secret: y = g^x, as well as all the shareholder "share
	 * public keys" g^s_i
	 * 
	 * @param message
	 * @throws DuplicateMessageReceivedException
	 * @throws StateViolationException
	 * @throws InvalidZeroKnowledgeProofException
	 */
	protected synchronized void deliverProofMessage(final PublicMessage message)
			throws DuplicateMessageReceivedException, StateViolationException, InvalidZeroKnowledgeProofException {

		// Ensure we have completed the sharing
		if (!this.isQualSetDefined) {
			throw new StateViolationException("Sharing has not yet completed");
		}

		// Check if we've seen one of these already
		final int senderIndex = message.getSenderIndex();
		if (this.receivedProofs[senderIndex - 1] != null) {
			throw new DuplicateMessageReceivedException("duplicate share contribution");
		}

		// The accuser is indicated in the rebuttal message
		final ZeroKnowledgeProof proof = (ZeroKnowledgeProof) message.getPayload().getData();

		// Ignore this proof, we've already received enough
		if (this.qualifiedProofs.size() < this.k) {

			// Interpolate pedersen commitments to the location of this shareholder
			final BigInteger x = BigInteger.valueOf(senderIndex);
			final EcPoint shareCommitment = PublicSharingGenerator.interpolatePedersonCommitments(x,
					this.pedersenCommitments);

			// Verify proof
			if (ZeroKnowledgeProver.verifyProof(shareCommitment, proof)) {

				// Add G^s_i to the set of qualified public keys
				this.qualifiedProofs.put(senderIndex, proof.getA0()); // Add g^si indexed by i

			} else {
				throw new InvalidZeroKnowledgeProofException("Shareholder " + senderIndex + " send an invalid proof");
			}

			// If size of qualified proofs == k, then interpolate the rest, including for
			// the public key
			if (this.qualifiedProofs.size() == this.k) {
				interpolatePublicKeys();
			}

		}
	}

	/**
	 * Determine the overall Public Key associated with the distributed secret "x",
	 * where y = g^x This is done by interpolating each of the values y_i = g^x_i,
	 * and then summing the g^x_i for all i in Qual
	 */
	private synchronized void interpolatePublicKeys() {

		// Use interpolation of the K published values to recover the public keys
		final List<DerivationResult> provenShareKeys = new ArrayList<>();

		for (final Entry<Integer, EcPoint> entry : this.qualifiedProofs.entrySet()) {
			final Integer i = entry.getKey();
			final EcPoint sharePublicKey = entry.getValue();
			final DerivationResult result = new DerivationResult(BigInteger.valueOf(i), sharePublicKey);
			provenShareKeys.add(result);
		}

		final List<DerivationResult> shareVerificationKeys = new ArrayList<>();
		for (int i = 0; i <= this.n; i++) {
			this.sharePublicKeys[i] = Polynomials.interpolateExponents(provenShareKeys, this.k, i);
			shareVerificationKeys.add(new DerivationResult(BigInteger.valueOf(i), this.sharePublicKeys[i]));
		}

		// Convert the share public keys to Feldman Coefficients using matrix inversion
		this.feldmanValues = Polynomials.interpolateCoefficientsExponents(shareVerificationKeys, this.k);

		final long endVerification = System.nanoTime();
		System.out.println("Time to establish verification keys: "
				+ (((double) (endVerification - startTime)) / 1_000_000_000.0) + " seconds");

		// Print our share
		System.out.println();
		System.out.println("Sharing Result:");
		System.out.println("This Server's Share:     s_" + this.index + "     =  " + this.getShare1());

		// Print secret verification key
		System.out.println("Secret Verification key: g^{s}   =  " + this.sharePublicKeys[0]);

		// Print share verification keys
		for (int i = 1; i <= n; i++) {
			System.out.println("Share Verification key:  g^{s_" + i + "} =  " + this.sharePublicKeys[i]);
		}

		// Print Feldman Coefficients
		for (int i = 0; i < k; i++) {
			System.out.println("Feldman Coefficient:     g^{a_" + i + "} =  " + this.feldmanValues[i]);
		}

		System.out.println("DKG Complete!");

		// System.out.println("Signatures generated: " + SigningUtil.signCount.get());
		// System.out.println("Signatures verified: " + SigningUtil.verCount.get());
	}

	/**
	 * Returns the unique index of this shareholder
	 * 
	 * @return
	 */
	public int getIndex() {
		return this.index;
	}

	/**
	 * Returns the public key of the secret: y = g^x
	 * 
	 * This method will return null if called before completion of the DKG protocol
	 * 
	 * @see waitForPublicKeys()
	 * 
	 * @return
	 */
	public EcPoint getSecretPublicKey() {
		return getSharePublicKey(0);
	}

	/**
	 * Returns the public key of the share for this shareholder: y_i = g^x_i
	 * 
	 * This method will return null if called before DKG protocol has built the
	 * public keys
	 * 
	 * @see waitForQual();
	 * 
	 * @return
	 */
	public EcPoint getSharePublicKey() {
		return getSharePublicKey(this.index);
	}

	public EcPoint getSharePublicKey(final int index) {
		return this.sharePublicKeys[index];
	}

	/**
	 * Return the set of shareholders who have contributed to the secret x
	 * 
	 * (Only used in tests)
	 * 
	 * @return
	 */
	protected SortedSet<Integer> getQualSet() {
		return new TreeSet<>(this.qualifiedSharings.keySet());
	}

	/**
	 * Return the secret share of this shareholder for g^s
	 * 
	 * (Only used in tests)
	 * 
	 * @return
	 */
	public ShamirShare getShare1() {
		return share1;
	}

	/**
	 * Return the secret share of this shareholder for h^s
	 * 
	 * (Only used in tests)
	 * 
	 * @return
	 */
	public ShamirShare getShare2() {
		return share2;
	}

	/**
	 * Wait until this shareholder has established the set of qualified shareholders
	 */
	public void waitForQual() {
		while (this.isQualSetDefined == false) {
			try {
				Thread.sleep(10);
			} catch (InterruptedException e) {
				// Ignored
			}
		}
	}

	/**
	 * Wait until this shareholder has constructed the public key: y = g^x
	 */
	public void waitForPublicKeys() {
		while (this.sharePublicKeys[0] == null) {
			try {
				Thread.sleep(10);
			} catch (InterruptedException e) {
				// Ignored
			}
		}
	}

	// TODO: Catch all instances of casting (check instance of) or catch
	// ClassCastException

}