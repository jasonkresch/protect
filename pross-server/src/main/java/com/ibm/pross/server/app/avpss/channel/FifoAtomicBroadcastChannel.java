package com.ibm.pross.server.app.avpss.channel;

import com.ibm.pross.server.messages.PublicMessage;

public interface FifoAtomicBroadcastChannel {

	/**
	 * Broadcasts a message to everyone on this channel
	 * 
	 * @param message
	 */
	public void send(final PublicMessage message);

	/**
	 * Returns the message by the index
	 * 
	 * @param messageIndex
	 * @return
	 */
	public PublicMessage getMessage(final long messageIndex);
	
	/**
	 * Returns the total number of messages that have been delivered to this channel
	 * @return
	 */
	public int getMessageCount();
	
}
