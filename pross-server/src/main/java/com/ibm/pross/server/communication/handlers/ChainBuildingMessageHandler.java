package com.ibm.pross.server.communication.handlers;

import java.io.IOException;
import java.security.PublicKey;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.ConcurrentSkipListSet;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;

import com.ibm.pross.common.util.serialization.Serialization;
import com.ibm.pross.server.app.avpss.channel.FifoAtomicBroadcastChannel;
import com.ibm.pross.server.channel.ChannelListener;
import com.ibm.pross.server.channel.ChannelSender;
import com.ibm.pross.server.channel.bft.BftAtomicBroadcastChannel;
import com.ibm.pross.server.communication.MessageDeliveryManager;
import com.ibm.pross.server.configuration.KeyLoader;
import com.ibm.pross.server.messages.Message;
import com.ibm.pross.server.messages.Payload;
import com.ibm.pross.server.messages.PublicMessage;
import com.ibm.pross.server.messages.SignedMessage;
import com.ibm.pross.server.messages.payloads.optbft.CertificationPayload;

/**
 * Connects the BFT layer to the Certified Opt chain
 */
public class ChainBuildingMessageHandler implements ChannelListener, MessageHandler, FifoAtomicBroadcastChannel {

	// Two chains which are maintained
	private final ConcurrentMap<Long, SignedMessage> bftChain = new ConcurrentHashMap<>();
	private final ConcurrentMap<Long, SignedMessage> optChain = new ConcurrentHashMap<>();
	
	// Maintain track of votes for various positions
	private final ConcurrentMap<Long, ConcurrentMap<SignedMessage, Set<Integer>>> votes = new ConcurrentHashMap<>();
	
	
	// Other fields
	private final KeyLoader keyLoader;
	private final int myIndex;
	private final int optQuorum;
	private final ChannelSender sender;

	private volatile MessageDeliveryManager messageManager;
	
	public ChainBuildingMessageHandler(final int myIndex, final int optQuorum, final KeyLoader keyLoader) {
		this.myIndex = myIndex;
		this.optQuorum = optQuorum;
		this.keyLoader = keyLoader;
		
		// Create instance of atomic broadcast channel, register to receive messages
		final BftAtomicBroadcastChannel channel = new BftAtomicBroadcastChannel();
		this.sender = channel.link(myIndex - 1);
		channel.register(this);
	}
	
	public MessageDeliveryManager getMessageManager() {
		return messageManager;
	}

	public void setMessageManager(MessageDeliveryManager messageManager) {
		this.messageManager = messageManager;
	}

	
	////////////////////////////////////////////////////////////////////////////////
	//                          Point-to-Point messages
	///////////////////////////////////////////////////////////////////////////////

	

	/**
	 * Handles message received over point-to-point links
	 */
	@Override
	public void handleMessage(final Message message) {

		// TODO: Implement stuff here
		System.out.println("OPT BFT --- Received unique authenticated message: " + message);

		// Count votes for messages in a given position
		if (message instanceof PublicMessage) {
			final PublicMessage publicMessage = (PublicMessage) message;
			final Payload payload = publicMessage.getPayload();
			if (payload instanceof CertificationPayload)
			{
				final CertificationPayload certificationPayload = (CertificationPayload) payload;
				final long messagePosition = certificationPayload.getMessagePosition();
				final SignedMessage bftMessage = certificationPayload.getBftMessage();
				recordVote(messagePosition, bftMessage, message.getSenderIndex());
			}
		}
	}
	
	private synchronized void recordVote(final long messagePosition, final SignedMessage bftMessage, final int voterId)
	{
		// Get the map for this position
		this.votes.putIfAbsent(messagePosition, new ConcurrentHashMap<SignedMessage, Set<Integer>>());
		final ConcurrentMap<SignedMessage, Set<Integer>> positionVotes = this.votes.get(messagePosition);
		
		// Get the set of votes for this message
		positionVotes.putIfAbsent(bftMessage, new ConcurrentSkipListSet<>());
		final Set<Integer> messageVotes = positionVotes.get(bftMessage);
		messageVotes.add(voterId);
		
		// Check if Opt-BFT quorum has been met
		if (messageVotes.size() == this.optQuorum)
		{
			System.err.println("QUORUM MET, added " + (optChain.size() + 1) + "th message to Opt-BFT Chain: " + bftMessage);
			this.optChain.put(messagePosition, bftMessage);
			this.notifyAll();
		}
	}
	
	
	////////////////////////////////////////////////////////////////////////////////
	//                          BFT
	///////////////////////////////////////////////////////////////////////////////

	/**
	 * Handles message received from the BFT
	 */
	@Override
	public synchronized void receiveSerializedMessage(final byte[] serializedMessage)
			throws ClassNotFoundException, IOException, BadPaddingException, IllegalBlockSizeException {

		// Deserialize the signed message sent as a TOM over the BFT Layer
		final SignedMessage bftMessage = (SignedMessage) Serialization.deserialize(serializedMessage);
		
		// Ensure it has a valid signature
		final PublicKey senderPublicKey = keyLoader.getVerificationKey(bftMessage.getMessage().getSenderIndex());
		if (!bftMessage.isSignatureValid(senderPublicKey))
		{
			// Ignore messages with invalid signatures
			return;
		}
		
		System.out.println("Received authenticated message over BFT channel: " + bftMessage);
		
		// Add BFT message to the BFT chain
		final long messagePosition = this.bftChain.size();
		this.bftChain.put(messagePosition, bftMessage);
		

		// Generate a certification message encapsulating this message along with our view of its position in the chain
		final CertificationPayload certificationPayload = new CertificationPayload(messagePosition, bftMessage);
		final PublicMessage publicMessage = new PublicMessage(this.myIndex, certificationPayload);
		
		// Broadcast our signature of this message and its position over point-to-point links
		this.messageManager.broadcast(publicMessage);
		
	}

	@Override
	public int getId() {
		return (this.myIndex - 1);
	}

	public void send(final Message message)
	{
		final SignedMessage signedMessage = new SignedMessage(message, keyLoader.getSigningKey());
		this.sender.broadcast(signedMessage);
	}
	
	public void send(final SignedMessage signedMessage)
	{
		this.sender.broadcast(signedMessage);
	}
	
	public int getMessageCount()
	{
		return this.optChain.size();
	}
	
	public Message getMessage(final long messageId)
	{
		// We don't need to return the signed message we we have already validated its signature
		return this.optChain.get(messageId).getMessage();
	}
}
