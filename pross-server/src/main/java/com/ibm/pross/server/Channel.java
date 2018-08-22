/*
 * Copyright (c) IBM Corporation 2018. All Rights Reserved.
 * Project name: pross
 * This project is licensed under the MIT License, see LICENSE.
 */

package com.ibm.pross.server;

import java.util.ArrayList;
import java.util.List;

import com.ibm.pross.common.util.serialization.Serialization;
import com.ibm.pross.server.messages.SignedMessage;
import com.ibm.pross.server.shareholder.Shareholder;

/**
 * Implements a synchronous broadcast channel which is a necessary building
 * block of proactive security
 */
public class Channel {

	private final List<Shareholder> registeredListeners = new ArrayList<>();

	/**
	 * Broadcasts messages to all shareholders who have registered with this
	 * channel
	 * 
	 * @param message
	 */
	public synchronized void broadcast(final SignedMessage message) {

		// Serialize message to bytes
		byte[] serializedMessage = Serialization.serializeClass(message);

		for (final Shareholder shareholder : this.registeredListeners) {
			shareholder.receiveSerializedMessage(serializedMessage);
		}

	}

	/**
	 * Registers a shareholder with the channel to receive messages
	 * 
	 * @param shareholder
	 */
	public synchronized void register(final Shareholder shareholder) {
		this.registeredListeners.add(shareholder);
	}

	/**
	 * Unregisters a shareholder with the channel (will no longer receive
	 * messages)
	 * 
	 * @param shareholder
	 */
	public synchronized void unregister(final Shareholder shareholder) {
		this.registeredListeners.remove(shareholder);
	}
}
