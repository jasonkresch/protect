package com.ibm.pross.server.channel;

import com.ibm.pross.server.messages.SignedMessage;

public interface ChannelSender {

	/**
	 * Broadcasts messages atomically to all shareholders who have registered with
	 * this channel
	 * 
	 * @param message
	 */
	public void broadcast(final SignedMessage message);

}
