package com.ibm.pross.server.communication;

import java.io.File;
import java.net.InetSocketAddress;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.Timer;
import java.util.TimerTask;

import com.ibm.pross.common.config.KeyLoader;
import com.ibm.pross.server.communication.handlers.MessageHandler;
import com.ibm.pross.server.communication.pointtopoint.MessageReceiver;
import com.ibm.pross.server.communication.pointtopoint.MessageSender;
import com.ibm.pross.server.messages.Message;
import com.ibm.pross.server.messages.RelayedMessage;
import com.ibm.pross.server.messages.SignedMessage;
import com.ibm.pross.server.messages.SignedRelayedMessage;
import com.ibm.pross.server.util.MessageSerializer;

/**
 * Tracks all of the connections related to a server
 */
public class MessageDeliveryManager {

	private final MessageStateTracker messageStateTracker;
	private final int myIndex;
	private final KeyLoader keyLoader;
	private final File saveLocation;
	private final MessageHandler messageHandler;

	final List<MessageSender> messageSenders;

	public static final int RESEND_DELAY = 3000; // 3 seconds
	private final Timer timer = new Timer(true);

	public MessageDeliveryManager(final List<InetSocketAddress> serverAddresses, final int myIndex,
			final KeyLoader keyLoader, final File saveLocation, final MessageHandler messageHandler,
			final MessageReceiver messageReceiver) {

		this.myIndex = myIndex;
		this.keyLoader = keyLoader;
		this.messageHandler = messageHandler;

		// Load persisted state from disk
		this.saveLocation = saveLocation;
		final File saveFile = new File(saveLocation, "message-state.dat");
		this.messageStateTracker = loadPersistedState(serverAddresses.size(), myIndex, saveFile);
		
		// Create a message sender for each server
		this.messageSenders = new ArrayList<>(serverAddresses.size());
		for (final InetSocketAddress serverAddress : serverAddresses) {
			messageSenders.add(new MessageSender(serverAddress.getHostName(), serverAddress.getPort()));
		}

		// Stubbornly send known messages until the recipient is a confirmed witness
		this.timer.scheduleAtFixedRate(new StubbornSendTask(), RESEND_DELAY, RESEND_DELAY);

		// Start thread to process messages from the messageReceiver
		final Thread messageReceiveProcessingThread = new Thread(() -> {
			while (true) {
				final byte[] rawMessage = messageReceiver.awaitNextMessage();
				try {
					final Object object = MessageSerializer.deserializeSignedRelayedMessage(rawMessage);
					if (object instanceof SignedRelayedMessage) {

						final SignedRelayedMessage signedRelayedMessage = (SignedRelayedMessage) object;
						// System.out.println("RAW Opt BFT --- Received signed relay message: " +
						// signedRelayedMessage);

						// Validate it, and process if necessary
						receive(signedRelayedMessage);
					}
				} catch (Throwable ignored) {
				}
			}
		});
		messageReceiveProcessingThread.start();
	}

	/**
	 * Load message tracking state from disk (failing that, start with an empty
	 * state)
	 * 
	 * @param numEntities
	 * @param myIndex
	 * @param saveLocation
	 * @return
	 */
	private static MessageStateTracker loadPersistedState(final int numEntities, final int myIndex,
			final File saveLocation) {
		//try {
		//	return (MessageStateTracker) AtomicFileOperations.readObject(saveLocation);
		//} catch (IOException e) {
			return new MessageStateTracker(numEntities, myIndex);
		//}
	}

	/**
	 * Save message tracking state to disk
	 * 
	 * @param messageStateTracker
	 * @param saveLocation
	 */
	private static void persistState(final MessageStateTracker messageStateTracker, final File saveLocation) {
		// FIXME: Get this working again, save only one message at a time.
//		try {
//			AtomicFileOperations.atomicWrite(saveLocation, messageStateTracker);
//		} catch (IOException e) {
//			throw new RuntimeException("Failed to persist state to disk:" + e);
//		}
	}

	// Periodic task for stubborn message delivery
	public class StubbornSendTask extends TimerTask {
		@Override
		public void run() {
			final Map<SignedMessage, Set<Integer>> pendingConfirmations = messageStateTracker
					.determineMessagesNotKnownByAll();

			//System.out.println("Resending " + pendingConfirmations.size() + " unconfirmed messages.");
			
			for (final Entry<SignedMessage, Set<Integer>> entry : pendingConfirmations.entrySet()) {
				final SignedMessage signedMessage = entry.getKey();
				final Set<Integer> recipients = entry.getValue();
				sendOnce(recipients, signedMessage);
			}
		}
	}

	public void receive(final SignedRelayedMessage signedRelayedMessage) {

		// Extract elements from the relayed message
		final RelayedMessage relayedMessage = signedRelayedMessage.getRelayedMessage();
		final int relayerId = relayedMessage.getRelayerId();
		final boolean isAcknowledgement = relayedMessage.isAcknowledgement();
		final SignedMessage signedMessage = relayedMessage.getSignedMessage();
		final int originatorId = signedMessage.getMessage().getSenderIndex();

		// Confirm outer relayed message signature before proceeding
		final PublicKey relayerPublicKey = this.keyLoader.getVerificationKey(relayerId);
		if (!signedRelayedMessage.isSignatureValid(relayerPublicKey)) {
			// Signature is bad, this could have come from anyone/anything
			// TODO: Log this but don't report a confirmed problem
			System.err.println("Bad relayer signature");
			return;
		}

		// Confirm inner signed message signature before proceeding
		// Unless it is an acknowledgement, which means we have seen it already
		// TODO: Figure out this optimization
		if (!isAcknowledgement) {
			final PublicKey originatorPublicKey = this.keyLoader.getVerificationKey(originatorId);
			if (!signedMessage.isSignatureValid(originatorPublicKey)) {
				// TODO: Warn about this, the relayer did not perform necessary checks before
				// passing message on
				System.err.println("Bad originator signature");
				return;
			}
		}

		// Process signed message
		receive(relayerId, isAcknowledgement, signedMessage);

		// Send a message acknowledgement (but only if this message is itself not an
		// acknowledgement)
		if (!isAcknowledgement) {
			this.sendAcknowledgement(relayerId, signedMessage);
		}
	}

	private void receive(final int relayerId, final boolean isAcknowledgement, final SignedMessage signedMessage) {
		// Record the signed message
		boolean isNew = this.messageStateTracker.recordMessage(relayerId, isAcknowledgement, signedMessage);

		// Persist the state of message state tracker to disk
		// We must do this before sending an acknowledgement
		//persistState(this.messageStateTracker, this.saveLocation);

		if (isNew) {
			// Handle the message
			this.messageHandler.handleMessage(signedMessage.getMessage());

			// If message was previously unknown, initiate an immediate broadcast
			// Note that we we will also stubbornly continue to send in the background
			final Set<Integer> unconfirmedRecipients = this.messageStateTracker
					.determineUnconfirmedWitnesses(signedMessage);
			sendOnce(unconfirmedRecipients, signedMessage);
		}
	}

	/**
	 * Initiate the broadcast of a new message out to the group
	 * 
	 * @param signedMessage
	 */
	public void broadcast(final Message message) {
		final SignedMessage signedMessage = new SignedMessage(message, keyLoader.getSigningKey());
		this.broadcast(signedMessage);
	}

	/**
	 * Initiate the broadcast of a new signed message out to the group
	 * 
	 * @param signedMessage
	 */
	public void broadcast(final SignedMessage signedMessage) {
		this.receive(this.myIndex, false, signedMessage);
	}

	/**
	 * Attempt one time to deliver a message to each recipient
	 * 
	 * @param recipients    The set of recipients (by their id) to deliver the
	 *                      message to
	 * @param signedMessage The signed message to deliver
	 */
	private void sendOnce(final Set<Integer> recipients, final SignedMessage signedMessage) {
		// Create SignedRelayedMessage
		final SignedRelayedMessage signedRelayedMessage = createSignedRelayedMessage(signedMessage, false);
		final byte[] messageContent = MessageSerializer.serializeSignedRelayedMessage(signedRelayedMessage);

		// Send to each recipient
		for (final Integer recipientIndex : recipients) {
			this.messageSenders.get(recipientIndex - 1).attemptMessageDelivery(messageContent);
		}
	}

	private void sendAcknowledgement(final int recipientIndex, final SignedMessage signedMessage) {
		// Create Acknowledgement of a received signedMessage
		final SignedRelayedMessage signedRelayedMessage = createSignedRelayedMessage(signedMessage, true);
		final byte[] messageContent = MessageSerializer.serializeSignedRelayedMessage(signedRelayedMessage);

		// Send acknowledgement (so they can validate us as a witness and stop sending
		// to us
		this.messageSenders.get(recipientIndex - 1).attemptMessageDelivery(messageContent);
	}

	private SignedRelayedMessage createSignedRelayedMessage(final SignedMessage signedMessage,
			boolean isAcknowledgement) {
		final RelayedMessage relayedMessage = new RelayedMessage(myIndex, isAcknowledgement, signedMessage);
		final PrivateKey signingKey = this.keyLoader.getSigningKey();
		return new SignedRelayedMessage(relayedMessage, signingKey);
	}

	public MessageHandler getMessageHandler() {
		return messageHandler;
	}

}
