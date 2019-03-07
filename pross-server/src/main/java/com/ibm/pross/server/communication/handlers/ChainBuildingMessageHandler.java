package com.ibm.pross.server.communication.handlers;

import java.io.File;
import java.io.IOException;
import java.security.PublicKey;
import java.util.AbstractMap.SimpleEntry;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.ConcurrentSkipListSet;
import java.util.concurrent.atomic.AtomicInteger;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;

import com.ibm.pross.server.app.avpss.channel.FifoAtomicBroadcastChannel;
import com.ibm.pross.server.channel.ChannelListener;
import com.ibm.pross.server.channel.ChannelSender;
import com.ibm.pross.server.channel.bft.BftAtomicBroadcastChannel;
import com.ibm.pross.server.communication.MessageDeliveryManager;
import com.ibm.pross.server.messages.Payload;
import com.ibm.pross.server.messages.Message;
import com.ibm.pross.server.messages.SignedMessage;
import com.ibm.pross.server.messages.payloads.optbft.CertificationPayload;
import com.ibm.pross.server.util.AtomicFileOperations;
import com.ibm.pross.server.util.MessageSerializer;

import bftsmart.reconfiguration.util.sharedconfig.KeyLoader;

/**
 * Connects the BFT layer to the Certified Opt chain
 */
public class ChainBuildingMessageHandler implements ChannelListener, MessageHandler, FifoAtomicBroadcastChannel {

	// Two chains which are maintained
	private final ConcurrentMap<Long, SignedMessage> bftChain = new ConcurrentHashMap<>();
	private final ConcurrentMap<Long, SignedMessage> optChain = new ConcurrentHashMap<>();
	private final AtomicInteger contiguousOptMessages = new AtomicInteger(0);

	// Maintain track of votes for various positions
	private final ConcurrentMap<Long, ConcurrentMap<SignedMessage, Set<Integer>>> votes = new ConcurrentHashMap<>();

	// Other fields
	private final KeyLoader keyLoader;
	private final int myIndex;
	private final int optQuorum;
	private final ChannelSender sender;

	private final BftAtomicBroadcastChannel bftChannel;

	private volatile MessageDeliveryManager messageManager;

	private final File bftMessageFolder;
	private final File certifiedMessageFolder;

	public ChainBuildingMessageHandler(final int myIndex, final int optQuorum, final KeyLoader keyLoader,
			final File saveLocation) {
		this.myIndex = myIndex;
		this.optQuorum = optQuorum;
		this.keyLoader = keyLoader;

		// Create instance of atomic broadcast channel, register to receive messages
		this.bftChannel = new BftAtomicBroadcastChannel();
		this.sender = this.bftChannel.link(myIndex - 1);
		this.bftChannel.register(this);

		// Create folders to track persisted chains
		this.bftMessageFolder = new File(saveLocation, "bft-chain");
		this.certifiedMessageFolder = new File(saveLocation, "certified-chain");
		bftMessageFolder.mkdirs();
		certifiedMessageFolder.mkdirs();
	}

	public boolean isBftReady() {
		return this.bftChannel.isReady();
	}

	public MessageDeliveryManager getMessageManager() {
		return messageManager;
	}

	public void setMessageManager(MessageDeliveryManager messageManager) {
		this.messageManager = messageManager;
	}

	////////////////////////////////////////////////////////////////////////////////
	// Point-to-Point messages
	///////////////////////////////////////////////////////////////////////////////

	/**
	 * Handles message received over point-to-point links
	 */
	@Override
	public void handleMessage(final Message message) {

		// TODO: Implement stuff here
		// System.out.println("OPT BFT --- Received unique authenticated message: " /*+
		// message*/);

		// Count votes for messages in a given position
		if (message instanceof Message) {
			final Message publicMessage = (Message) message;
			final Payload payload = publicMessage.getPayload();
			if (payload.getOpcode() == Payload.OpCode.BFT_CERTIFICATION) {
				final SimpleEntry<Long, SignedMessage> data = (SimpleEntry<Long, SignedMessage>) payload.getData();
				final long messagePosition = data.getKey();
				final SignedMessage bftMessage = data.getValue();
				recordVote(messagePosition, bftMessage, message.getSenderIndex());
			}
		}
	}

	private synchronized void recordVote(final long messagePosition, final SignedMessage bftMessage,
			final int voterId) {
		// Get the map for this position
		this.votes.putIfAbsent(messagePosition, new ConcurrentHashMap<SignedMessage, Set<Integer>>());
		final ConcurrentMap<SignedMessage, Set<Integer>> positionVotes = this.votes.get(messagePosition);

		// Get the set of votes for this message
		positionVotes.putIfAbsent(bftMessage, new ConcurrentSkipListSet<>());
		final Set<Integer> messageVotes = positionVotes.get(bftMessage);
		messageVotes.add(voterId);

		// Check if Opt-BFT quorum has been met
		if (messageVotes.size() == this.optQuorum) {
			// System.err.println("QUORUM MET, added " + (optChain.size() + 1) + "th message
			// to Opt-BFT Chain: " /*+ bftMessage*/);
			synchronized (this.optChain) {

				System.out.println("Certified message #" + (messagePosition + 1) + " is available.");
				if (this.optChain.putIfAbsent(messagePosition + 1, bftMessage) == null) {

					// Increment contiguousOptMessages if we are contiguous
					while (this.optChain.containsKey(new Long(contiguousOptMessages.get() + 1))) {
						contiguousOptMessages.incrementAndGet();
					}

					final String msgFileName = String.format("%08d", messagePosition + 1) + ".msg";
					final File messageFile = new File(this.certifiedMessageFolder, msgFileName);
					try {
						AtomicFileOperations.atomicWriteSignedMessage(messageFile, bftMessage);
					} catch (IOException e) {
						e.printStackTrace();
						System.exit(-1);
					}
					this.notifyAll();
				}
			}
		}
	}

	////////////////////////////////////////////////////////////////////////////////
	// BFT
	///////////////////////////////////////////////////////////////////////////////

	/**
	 * Handles message received from the BFT
	 */
	@Override
	public synchronized void receiveSerializedMessage(final byte[] serializedMessage)
			throws ClassNotFoundException, IOException, BadPaddingException, IllegalBlockSizeException {

		// Deserialize the signed message sent as a TOM over the BFT Layer
		final SignedMessage bftMessage = MessageSerializer.deserializeSignedMessage(serializedMessage);

		// Ensure it has a valid signature
		final PublicKey senderPublicKey = keyLoader.getVerificationKey(bftMessage.getMessage().getSenderIndex());
		if (!bftMessage.isSignatureValid(senderPublicKey)) {
			// Ignore messages with invalid signatures
			return;
		}

		// System.out.println("Received new BFT message"); //: " /*+ bftMessage*/);

		// Add BFT message to the BFT chain
		synchronized (this.bftChain) {
			final long messagePosition = this.bftChain.size();
			this.bftChain.put(messagePosition, bftMessage);

			final String msgFileName = String.format("%08d", messagePosition + 1) + ".msg";
			final File messageFile = new File(this.bftMessageFolder, msgFileName);
			try {
				AtomicFileOperations.atomicWriteSignedMessage(messageFile, bftMessage);
			} catch (IOException e) {
				e.printStackTrace();
				System.exit(-1);
			}

			// Generate a certification message encapsulating this message along with our
			// view of its position in the chain
			final CertificationPayload certificationPayload = new CertificationPayload(messagePosition, bftMessage);
			final Message publicMessage = new Message("certification", this.myIndex, certificationPayload);

			// Broadcast our signature of this message and its position over point-to-point
			// links
			this.messageManager.broadcast(publicMessage);

			// Fix this: (can simulate skipping the Certification Layer)
			// Add message straight to the opt chain and signal
			// this.optChain.putIfAbsent(new Long(this.optChain.size()), bftMessage);
			// this.notifyAll();
		}
	}

	@Override
	public int getId() {
		return (this.myIndex - 1);
	}

	public void send(final Message message) {
		final SignedMessage signedMessage = new SignedMessage((Message) message, keyLoader.getSigningKey());
		this.sender.broadcast(signedMessage);
	}

	public void send(final SignedMessage signedMessage) {
		this.sender.broadcast(signedMessage);
	}

	public synchronized int getMessageCount() {
		synchronized (this.optChain) {
			// Must return only the size of contiguous messages
			return contiguousOptMessages.get();
		}
	}

	public synchronized Message getMessage(final long messageId) {
		synchronized (this.optChain) {
			// We don't return the signed message we we have already validated its signature
			final SignedMessage signedMessage = this.optChain.get(messageId);
			if (signedMessage == null) {
				return null; // We might have certified messages in different orders
			} else {
				return signedMessage.getMessage();
			}
		}
	}
}
