package com.ibm.pross.server.app.avpss.channel;

import com.ibm.pross.server.messages.Message;

public interface FifoAtomicBroadcastChannel {

	/**
	 * Broadcasts a message to everyone on this channel
	 * 
	 * @param message
	 */
	public void send(final Message message);

	/**
	 * Returns the message by the index
	 * 
	 * @param messageIndex
	 * @return
	 */
	public Message getMessage(final long messageIndex);
	
	/**
	 * Returns the total number of messages that have been delivered to this channel
	 * @return
	 */
	public int getMessageCount();
	
}
