package com.ibm.pross.server.channel;

import java.io.IOException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;

/**
 * Interface for an entity that receives messages from the broadcast channel
 */
public interface ChannelListener {

	/**
	 * The method that gets invoked when a message is broadcast on the channel
	 * 
	 * @param serializedMessage
	 * @throws IOException
	 * @throws ClassNotFoundException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 */
	public void receiveSerializedMessage(final byte[] serializedMessage)
			throws ClassNotFoundException, IOException, BadPaddingException, IllegalBlockSizeException;

	/**
	 * A unique identifier for this listener
	 * 
	 * @return
	 */
	public int getId();

}
