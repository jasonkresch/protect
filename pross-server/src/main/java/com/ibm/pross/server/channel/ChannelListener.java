package com.ibm.pross.server.channel;

/**
 * Interface for an entity that receives messages from the broadcast channel
 */
public interface ChannelListener {

	/**
	 * The method that gets invoked when a message is broadcast on the channel
	 * 
	 * @param serializedMessage
	 */
	public void receiveSerializedMessage(final byte[] serializedMessage);

	/**
	 * A unique identifier for this listener
	 * 
	 * @return
	 */
	public int getId();

}
