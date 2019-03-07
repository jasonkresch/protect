/*
 * Copyright (c) IBM Corporation 2018. All Rights Reserved.
 * Project name: pross
 * This project is licensed under the MIT License, see LICENSE.
 */

package com.ibm.pross.server.messages;

import java.io.Serializable;

public class PublicMessage implements Serializable {

	private static final long serialVersionUID = -8470206987302692599L;

	// The name of the channel over which this message will be sent
	private final String channelName;
	
	// Always set to the index of the shareholder who created and sent this
	// message. Sender index is used to determine the public key by which to
	// verify the message authenticity
	private final int senderIndex;

	// The content of the message
	private final Payload payload;

	/**
	 * Constructs a publicly readable broadcast message
	 * 
	 * @param senderIndex
	 *            The index of the sender (ourself)
	 * @param content
	 *            The content of the message to send
	 */
	public PublicMessage(final String channelName, final int senderIndex, final Payload payload) {
		this.channelName = channelName;
		this.senderIndex = senderIndex;
		this.payload = payload;
	}
	
	public Payload getPayload()
	{
		return payload;
	}

	/**
	 * Returns the index of the shareholder who purportedly sent this message.
	 * 
	 * @return
	 */
	public int getSenderIndex() {
		return this.senderIndex;
	}

	/**
	 * Determines whether the provided channel name indicates the shareholder is a recipient  for this message
	 * 
	 * @param channelName
	 *            The channel name of the shareholder
	 * @return Returns true if the provided shareholder index is a recipient of
	 *         the message
	 */
	public boolean isRecipient(final String channelName) {
		return this.channelName.equals(channelName);
	}

	/**
	 * Returns the name of the channel for this message
	 * @return
	 */
	public String getChannelName() {
		return this.channelName;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((channelName == null) ? 0 : channelName.hashCode());
		result = prime * result + ((payload == null) ? 0 : payload.hashCode());
		result = prime * result + senderIndex;
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		PublicMessage other = (PublicMessage) obj;
		if (channelName == null) {
			if (other.channelName != null)
				return false;
		} else if (!channelName.equals(other.channelName))
			return false;
		if (payload == null) {
			if (other.payload != null)
				return false;
		} else if (!payload.equals(other.payload))
			return false;
		if (senderIndex != other.senderIndex)
			return false;
		return true;
	}

	@Override
	public String toString() {
		return "PublicMessage [channelName=" + channelName + ", senderIndex=" + senderIndex + ", payload=" + payload
				+ "]";
	}

	
}
