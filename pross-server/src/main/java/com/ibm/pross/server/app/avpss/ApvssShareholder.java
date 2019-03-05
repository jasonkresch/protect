package com.ibm.pross.server.app.avpss;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.SortedSet;
import java.util.Timer;
import java.util.TimerTask;
import java.util.TreeSet;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

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
import com.ibm.pross.server.app.avpss.messages.PublicSharingPayload;
import com.ibm.pross.server.app.avpss.messages.ZkpPayload;
import com.ibm.pross.server.messages.Message;
import com.ibm.pross.server.messages.Payload.OpCode;
import com.ibm.pross.server.messages.PublicMessage;

import bftsmart.reconfiguration.util.sharedconfig.KeyLoader;

public class ApvssShareholder {

	public enum SharingType {
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
	private final AtomicLong currentMessageId = new AtomicLong(0);

	// Our message processing thread
	private final Thread messageProcessingThread;
	private final AtomicBoolean stopped = new AtomicBoolean(true);

	// Our timer task for doing proactive refresh
	private final Timer timer = new Timer(true);

	/********************** Misc Info ******************************/
	// The unique name for this secret
	private final String secretName;

	// How the secret was established
	private volatile SharingType sharingType;

	private AtomicBoolean enabled = new AtomicBoolean(true);

	/*****************************************************************/

	// The index of this shareholder (ourself) (one is the base index)
	// This shareholder will hold the share at f(index)
	private final int index;

	// The number of shareholders
	private final int n;

	// The recovery threshold of the secret
	private final int k;

	// Used to misbehave
	private final boolean sendValidCommitments;

	// Track each epoch separately
	private final Map<Long, SharingState> sharingStates = new ConcurrentHashMap<>();
	private final AtomicLong currentEpoch = new AtomicLong(0);
	private final AtomicLong nextEpoch = new AtomicLong(0);
	private final AtomicLong[] shareholderMessageCounts;
	
	// Used to hold an initial share of a secret (to supported stored secrets)
	private volatile BigInteger storedShareOfSecret = null;

	public ApvssShareholder(final String secretName, final KeyLoader keyLoader,
			final FifoAtomicBroadcastChannel channel, final int index, final int n, final int k) {
		this(secretName, keyLoader, channel, index, n, k, true);
	}

	public ApvssShareholder(final String secretName, final KeyLoader keyLoader,
			final FifoAtomicBroadcastChannel channel, final int index, final int n, final int k,
			final boolean sendValidCommitments) {

		this.secretName = secretName;

		// Start first epoch
		this.sharingStates.put(currentEpoch.get(), new SharingState(n, k, 0));

		// Track message counts from senders
		this.shareholderMessageCounts = new AtomicLong[n];
		for (int i = 0; i < n; i++) {
			this.shareholderMessageCounts[i] = new AtomicLong(0);
		}

		this.sendValidCommitments = sendValidCommitments;

		/** Values unique to ourselves **/
		this.index = index;

		/** Public shared configuration parameters **/
		this.keyLoader = keyLoader;
		this.channel = channel;
		this.n = n;
		this.k = k; // reconstruction threshold (usually f_S + 1)

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
							channel.wait(100);
						}
					} catch (InterruptedException e) {
						// Ignore
					}
				}
			}
		}, "Shareholder-Thread-" + this.index);
	}

	// Periodic task for stubborn message delivery
	public class RefreshTask extends TimerTask {
		@Override
		public void run() {
			final long currentEpoch = ApvssShareholder.this.nextEpoch.get();
			final long nextEpoch = ApvssShareholder.this.nextEpoch.incrementAndGet();
			System.out.println("Performing Refresh for secret '" + ApvssShareholder.this.secretName + "' epoch: ("
					+ currentEpoch + " -> " + nextEpoch + ")");
			broadcastPublicSharing(nextEpoch);
		}
	}

	/**
	 * A message is available on the queue, get it and deliver it for processing
	 */
	private synchronized void messageIsAvailable() {

		final long messageId = this.currentMessageId.incrementAndGet();
		final Message message = this.channel.getMessage(messageId);

		// TODO: Remove this debugging text
		// long messageCount = this.channel.getMessageCount();
		// System.err.println(messageCount + ";" + messageId);

		// Deliver only if this message is relevant for the given epoch and secret
		final String channelName = this.secretName;
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

			// Track how many messages have been received from this shareholder
			final int senderId = message.getSenderIndex();
			final long messageCount = this.shareholderMessageCounts[senderId - 1].getAndIncrement();
			final long senderEpoch = messageCount / 2;

			try {

				// Make sure the sender hasn't gotten too far ahead (we should have the previous
				// sharing already)
				if (senderEpoch > this.nextEpoch.get()) {
					// throw new StateViolationException("Sender is getting too far ahead");
				}

				switch (opcode) {
				case PS:
					deliverPublicSharing(senderEpoch, (PublicMessage) message);
					break;
				case ZK:
					deliverProofMessage(senderEpoch, (PublicMessage) message);
					break;
				case NOOP:
					// Do nothing
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
				broadcastPublicSharing(0);
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

	private long getCurrentEpoch() {
		return currentEpoch.get();
	}

	public SharingState getSharing(final long epochNumber) {
		synchronized (this.sharingStates) {
			this.sharingStates.putIfAbsent(epochNumber, new SharingState(n, k, epochNumber));
			return this.sharingStates.get(epochNumber);
		}
	}

	private SharingState getCurrentSharing() {
		return getSharing(getCurrentEpoch());
	}

	/**
	 * Send out initial message containing our Public Sharing (privately encrypted
	 * shares to each peer shareholder, proofs of correctness and our Pedersen
	 * commitments. This will start the DKG protocol based on APVSS, and it will be
	 * driven to completion.
	 */
	public boolean broadcastPublicSharing(final long epoch) {

		// Get sharing state for the current epoch
		final SharingState sharingState = getSharing(epoch);

		if (sharingState.getBroadcastSharing().compareAndSet(false, true)) {

			sharingState.setStartTime(System.nanoTime());

			// Get shareholder public encryption keys
			final PaillierPublicKey[] publicKeys = new PaillierPublicKey[n];
			for (int i = 1; i <= n; i++) {
				publicKeys[i - 1] = (PaillierPublicKey) this.keyLoader.getEncryptionKey(i);
			}

			// Create Public Sharing (if first DKG use random, otherwise use share)
			final PublicSharingGenerator generator = new PublicSharingGenerator(this.n, this.k);
			final PublicSharing publicSharing;
			if (epoch == 0) {
				System.out.println("Starting DKG operation!");
				if (storedShareOfSecret == null) {
					// No share was stored, do a DKG of a random value
					publicSharing = generator.shareRandomSecret(publicKeys);
					this.sharingType = SharingType.PEDERSEN_DKG;
				} else {
					// A share was pre-stored, do a DKG using this value
					publicSharing = generator.shareSecret(storedShareOfSecret, publicKeys);
					this.storedShareOfSecret = null; // Wipe it for proactive security
					this.sharingType = SharingType.STORED;
				}
			} else {
				if (getSharing(epoch - 1).getShare1() != null) {
					final BigInteger share1 = getSharing(epoch - 1).getShare1().getY();
					final BigInteger share2 = getSharing(epoch - 1).getShare2().getY();
					publicSharing = generator.shareSecretAndRandomness(share1, share2, publicKeys);
				} else {
					// Share was deleted, send a null contribution
					publicSharing = null;
				}
			}

			// Create a message
			final PublicSharingPayload payload = new PublicSharingPayload(publicSharing);
			final String channelName = this.secretName;
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
	 * @param senderEpoch
	 * 
	 * @param message
	 * @throws DuplicateMessageReceivedException
	 * @throws InvalidCiphertextException
	 * @throws InconsistentShareException
	 * @throws StateViolationException
	 */
	protected synchronized void deliverPublicSharing(final long senderEpoch, final PublicMessage message)
			throws DuplicateMessageReceivedException, InvalidCiphertextException, InconsistentShareException,
			StateViolationException {

		// Get sharing state for the current epoch
		final SharingState sharingState = getSharing(senderEpoch);

		// A DKG is starting, broadcast sharing if we have not already done so
		if ((senderEpoch == 0) && (this.currentEpoch.get() == 0) && (this.getSecretPublicKey() == null)) {
			if (!sharingState.getBroadcastSharing().get()) {
				broadcastPublicSharing(0); // First DKG triggered by someone else, all other proactive by us
			}
		}

		// Check if we've seen one of these already
		final int senderIndex = message.getSenderIndex();
		if (sharingState.getReceivedSharings()[senderIndex - 1] != null) {
			throw new DuplicateMessageReceivedException("duplicate share contribution");
		}

		// Extract the payload
		final PublicSharing publicSharing = (PublicSharing) message.getPayload().getData();

		if (publicSharing == null) {
			// This shareholder lost a share, ignore
			return;
		}

		// Save it
		sharingState.getReceivedSharings()[senderIndex - 1] = publicSharing;

		// Ensure sharing matches our n and t
		if (publicSharing.getNumShares() != this.n) {
			throw new InconsistentShareException("incorrect n");
		}
		if (publicSharing.getThreshold() != this.k) {
			throw new InconsistentShareException("incorrect k");
		}

		// Get shareholder public encryption keys
		final PaillierPublicKey[] shareholderKeys = new PaillierPublicKey[n];
		for (int i = 1; i <= this.n; i++) {
			shareholderKeys[i - 1] = (PaillierPublicKey) this.keyLoader.getEncryptionKey(i);
		}

		// Verify the shares are correct
		if (!publicSharing.verifyAllShares(shareholderKeys)) {
			throw new InvalidCiphertextException("Public Sharing was not valid");
		}

		// Verify consistency with the previous commitment g_^{s_i} * h^{r_i}
		if (senderEpoch > 0) {
			final EcPoint secretCommitment = publicSharing.getSecretCommitment();

			final SharingState previousSharing = this.getSharing(senderEpoch - 1);
			final EcPoint previousShareCommitment = PublicSharingGenerator.interpolatePedersonCommitments(
					BigInteger.valueOf(senderIndex), previousSharing.getPedersenCommitments());

			if (!secretCommitment.equals(previousShareCommitment)) {
				throw new InconsistentShareException("Shareholder sent an invalid sharing");
			}
		}

		// It is valid, increment success count
		final int successes = sharingState.getSuccessCount().incrementAndGet();
		if (successes <= k) {
			// We are still building the qual set, add it
			sharingState.getQualifiedSharings().put(senderIndex, publicSharing);
		}

		if (successes == this.k) {
			// We have reached a threshold to proceed to next phase
			assembleCombinedShareByInterpolation(senderEpoch);
		}
	}

	/**
	 * Complete the DKG by combining all the PVSSs in Qual (via interpolation,
	 * rather than summation)
	 */
	private synchronized void assembleCombinedShareByInterpolation(final long senderEpoch) {

		// Get sharing state for the current epoch
		final SharingState sharingState = getSharing(senderEpoch);

		// Determine list of contributors
		final List<Integer> contributors = new ArrayList<>(sharingState.getQualifiedSharings().keySet());
		Collections.sort(contributors);
		final BigInteger[] xCoords = contributors.stream().map(i -> BigInteger.valueOf(i)).toArray(BigInteger[]::new);

		// final BigInteger[] xCoords =
		// sharingState.getQualifiedSharings().keySet().stream()
		// .map(i -> BigInteger.valueOf(i)).toArray(BigInteger[]::new);

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
		for (final Integer contributor : contributors) {

			final BigInteger j = BigInteger.valueOf(contributor);
			final PublicSharing sharing = sharingState.getQualifiedSharings().get(contributor);

			// Decrypt our shares
			final ShamirShare share1 = sharing.accessShare1(index - 1, decryptionKey);
			final ShamirShare share2 = sharing.accessShare2(index - 1, decryptionKey);

			// Get the commitments
			final EcPoint[] commitments = sharing.getPedersenCommitments();

			// Compute lagrange co-efficient
			final BigInteger l = Polynomials.interpolatePartial(xCoords, BigInteger.ZERO, j, curve.getR());

			// Add the shares to our running sum
			share1Y = share1Y.add(share1.getY().multiply(l)).mod(curve.getR());
			share2Y = share2Y.add(share2.getY().multiply(l)).mod(curve.getR());

			// Add Pedersen commitments to our running sum
			for (int i = 0; i < this.k; i++) {
				final EcPoint interpolatedCommitment = curve.multiply(commitments[i], l);
				combinedPedersenCommitments[i] = curve.addPoints(combinedPedersenCommitments[i],
						interpolatedCommitment);
			}
		}

		// We have our shares
		sharingState.setShare1(new ShamirShare(BigInteger.valueOf(this.index), share1Y));
		sharingState.setShare2(new ShamirShare(BigInteger.valueOf(this.index), share2Y));

		// We have our Pedersen commitments
		sharingState.setPedersenCommitments(combinedPedersenCommitments);

		// Broadcast ZKP of a splitting
		broadcastZkp(senderEpoch);

		sharingState.setQualSetDefined(true);

		final long shareEnd = System.nanoTime();
		final long startTime = sharingState.getStartTime();
		System.out.println("Time to establish share:             "
				+ (((double) (shareEnd - startTime)) / 1_000_000_000.0) + " seconds");
	}

	/**
	 * Broadcast a ZKP of our shares From these, we can interpolate all the share
	 * public keys
	 */
	private void broadcastZkp(final long senderEpoch) {

		// Get sharing state for the current epoch
		final SharingState sharingState = getSharing(senderEpoch);

		final ZeroKnowledgeProof proof;
		if (sharingState.getShare1() != null) {

			// S = g^s_i
			// R = h^r_i
			final BigInteger s = sharingState.getShare1().getY();
			final BigInteger r = sharingState.getShare2().getY();

			// Prove: g^s_i * h^r_i = S (Pedersen commitment)

			if (this.sendValidCommitments) {
				proof = ZeroKnowledgeProver.createProof(s, r);
			} else {
				// Simulate malfunction
				proof = ZeroKnowledgeProver.createProof(s, r.add(BigInteger.ONE));
			}
		} else {
			// Our share is missing, send a null proof
			proof = null;
		}

		// Send message out
		final ZkpPayload payload = new ZkpPayload(proof);
		final String channelName = this.secretName;
		this.channel.send(new PublicMessage(channelName, this.index, payload));
	}

	/**
	 * Process a proof sent by another shareholder. These will be used to determine
	 * the public key of the secret: y = g^x, as well as all the shareholder "share
	 * public keys" g^s_i
	 * 
	 * @param senderEpoch
	 * 
	 * @param message
	 * @throws DuplicateMessageReceivedException
	 * @throws StateViolationException
	 * @throws InvalidZeroKnowledgeProofException
	 */
	protected synchronized void deliverProofMessage(final long senderEpoch, final PublicMessage message)
			throws DuplicateMessageReceivedException, StateViolationException, InvalidZeroKnowledgeProofException {

		// Get sharing state for the current epoch
		final SharingState sharingState = getSharing(senderEpoch);

		// Ensure we have completed the sharing
		if (!sharingState.isQualSetDefined()) {
			throw new StateViolationException("Sharing has not yet completed");
		}

		// Check if we've seen one of these already
		final int senderIndex = message.getSenderIndex();
		if (sharingState.getReceivedProofs()[senderIndex - 1] != null) {
			throw new DuplicateMessageReceivedException("duplicate share contribution");
		}

		// The accuser is indicated in the rebuttal message
		final ZeroKnowledgeProof proof = (ZeroKnowledgeProof) message.getPayload().getData();

		if (proof == null) {
			// Sender lost their share, ignore
			return;
		}
		
		// Ignore this proof, we've already received enough
		if (sharingState.getQualifiedProofs().size() < this.k) {

			// Interpolate pedersen commitments to the location of this shareholder
			final BigInteger x = BigInteger.valueOf(senderIndex);
			final EcPoint shareCommitment = PublicSharingGenerator.interpolatePedersonCommitments(x,
					sharingState.getPedersenCommitments());

			// Verify proof
			if (ZeroKnowledgeProver.verifyProof(shareCommitment, proof)) {

				// Add G^s_i to the set of qualified public keys
				sharingState.getQualifiedProofs().put(senderIndex, proof.getA0()); // Add g^si indexed by i

			} else {
				throw new InvalidZeroKnowledgeProofException("Shareholder " + senderIndex + " send an invalid proof");
			}

			// If size of qualified proofs == k, then interpolate the rest, including for
			// the public key
			if (sharingState.getQualifiedProofs().size() == this.k) {
				interpolatePublicKeys(senderEpoch);

				if (senderEpoch > this.getCurrentEpoch()) {
					final long newEpoch = currentEpoch.incrementAndGet();
					System.out.println("Refresh complete for secret '" + ApvssShareholder.this.secretName
							+ "', now at epoch: " + newEpoch);
				}
			}
		}
	}

	/**
	 * Determine the overall Public Key associated with the distributed secret "x",
	 * where y = g^x This is done by interpolating each of the values y_i = g^x_i,
	 * and then summing the g^x_i for all i in Qual
	 */
	private synchronized void interpolatePublicKeys(final long senderEpoch) {

		// Get sharing state for the current epoch
		final SharingState sharingState = getSharing(senderEpoch);

		// Use interpolation of the K published values to recover the public keys
		final List<DerivationResult> provenShareKeys = new ArrayList<>();

		for (final Entry<Integer, EcPoint> entry : sharingState.getQualifiedProofs().entrySet()) {
			final Integer i = entry.getKey();
			final EcPoint sharePublicKey = entry.getValue();
			final DerivationResult result = new DerivationResult(BigInteger.valueOf(i), sharePublicKey);
			provenShareKeys.add(result);
		}

		final List<DerivationResult> shareVerificationKeys = new ArrayList<>();
		for (int i = 0; i <= this.n; i++) {
			sharingState.getSharePublicKeys()[i] = Polynomials.interpolateExponents(provenShareKeys, this.k, i);
			shareVerificationKeys
					.add(new DerivationResult(BigInteger.valueOf(i), sharingState.getSharePublicKeys()[i]));
		}

		// Convert the share public keys to Feldman Coefficients using matrix inversion
		sharingState.setFeldmanValues(Polynomials.interpolateCoefficientsExponents(shareVerificationKeys, this.k));

		final long startTime = sharingState.getStartTime();
		final long endVerification = System.nanoTime();
		System.out.println("Time to establish verification keys: "
				+ (((double) (endVerification - startTime)) / 1_000_000_000.0) + " seconds");

		// Print our share
		System.out.println();
		System.out.println("Sharing Result:");
		System.out.println("This Server's Share:     s_" + this.index + "     =  " + sharingState.getShare1());

		// Print secret verification key
		System.out.println("Secret Verification key: g^{s}   =  " + sharingState.getSharePublicKeys()[0]);

		// Print share verification keys
		for (int i = 1; i <= n; i++) {
			System.out.println("Share Verification key:  g^{s_" + i + "} =  " + sharingState.getSharePublicKeys()[i]);
		}

		// Print Feldman Coefficients
		for (int i = 0; i < k; i++) {
			System.out.println("Feldman Coefficient:     g^{a_" + i + "} =  " + sharingState.getFeldmanValues()[i]);
		}

		sharingState.setCreationTime(new Date());

		if (senderEpoch == 0) {
			System.out.println("DKG Complete!");
		} else {
			System.out.print("Refresh Complete!");

			// Sanity check, make sure public keys match before advancing epoch state
			if (this.getCurrentSharing().getSharePublicKeys()[0].equals(sharingState.getSharePublicKeys()[0])) {
				System.out.println(" Consistency with previous epoch has been verified.");

				// Delete the previous share
				this.getCurrentSharing().setShare1(null);

			} else {
				throw new RuntimeException("Our new sharing is inconsistent with the previous epoch.");
			}

		}

		// Schedule Proactive Refresh Task
		System.out.println("Scheduling next Refresh to occur in " + this.getRefreshFrequency() + " seconds");
		final int refreshPeriodMillis = this.getRefreshFrequency() * 1000;
		this.timer.schedule(new RefreshTask(), refreshPeriodMillis);

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
		return getCurrentSharing().getSharePublicKeys()[index];
	}

	public EcPoint getFeldmanValues(final int index) {
		return getCurrentSharing().getFeldmanValues()[index];
	}

	public int getN() {
		return this.n;
	}

	public int getK() {
		return this.k;
	}

	/**
	 * Return the set of shareholders who have contributed to the secret x
	 * 
	 * (Only used in tests)
	 * 
	 * @return
	 */
	protected SortedSet<Integer> getQualSet() {
		return new TreeSet<>(getCurrentSharing().getQualifiedSharings().keySet());
	}

	/**
	 * Return the secret share of this shareholder for g^s
	 * 
	 * (Only used in tests)
	 * 
	 * @return
	 */
	public ShamirShare getShare1() {
		return getCurrentSharing().getShare1();
	}

	/**
	 * Return the secret share of this shareholder for h^s
	 * 
	 * (Only used in tests)
	 * 
	 * @return
	 */
	public ShamirShare getShare2() {
		return getCurrentSharing().getShare2();
	}

	/**
	 * Wait until this shareholder has established the set of qualified shareholders
	 */
	public void waitForQual() {

		// Get sharing state for the current epoch
		final SharingState sharingState = getCurrentSharing();

		while (sharingState.isQualSetDefined() == false) {
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

		// Get sharing state for the current epoch
		final SharingState sharingState = getCurrentSharing();

		while (sharingState.getSharePublicKeys()[0] == null) {
			try {
				Thread.sleep(10);
			} catch (InterruptedException e) {
				// Ignored
			}
		}
	}

	public Date getCreationTime() {
		// Creation time of the secret is when the 0th epoch completed
		return this.sharingStates.get(new Long(0)).getCreationTime();
	}

	public long getEpoch() {
		return getCurrentSharing().getEpochNumber();
	}

	public Date getLastRefreshTime() {
		return getCurrentSharing().getCreationTime();
	}

	public int getRefreshFrequency() {
		return 30;
	}

	public SharingType getSharingType() {
		return this.sharingType;
	}

	public boolean isEnabled() {
		return this.enabled.get();
	}

	public void setEnabled(boolean isEnabled) {
		this.enabled.set(isEnabled);
	}
	
	public BigInteger getStoredShareOfSecret() {
		return storedShareOfSecret;
	}

	public void setStoredShareOfSecret(BigInteger storedShareOfSecret) {
		this.storedShareOfSecret = storedShareOfSecret;
	}

	public void deleteShare() {
		getCurrentSharing().setShare1(null);
	}

	// TODO: Catch all instances of casting (check instance of) or catch
	// ClassCastException

}