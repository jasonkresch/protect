package com.ibm.pross.server.channel.local;

import java.util.List;

import com.ibm.pross.common.util.serialization.Serialization;
import com.ibm.pross.server.channel.ChannelListener;
import com.ibm.pross.server.channel.ChannelSender;
import com.ibm.pross.server.messages.SignedMessage;

public class LocalChannelSender implements ChannelSender {

	private final List<ChannelListener> registeredListeners;
	
	public LocalChannelSender(final List<ChannelListener> registeredListeners) {
		this.registeredListeners = registeredListeners;
	}

	/**
	 * Broadcasts messages to all listeners who have registered with this channel
	 * 
	 * @param message
	 */
	@Override
	public void broadcast(final SignedMessage message) {

		synchronized (this.registeredListeners)
		{
			// Serialize message to bytes
			byte[] serializedMessage = Serialization.serializeClass(message);
	
			for (final ChannelListener listener : this.registeredListeners) {
				listener.receiveSerializedMessage(serializedMessage);
			}
		}

	}

}
