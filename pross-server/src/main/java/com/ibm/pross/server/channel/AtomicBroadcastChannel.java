/*
 * Copyright (c) IBM Corporation 2018. All Rights Reserved.
 * Project name: pross
 * This project is licensed under the MIT License, see LICENSE.
 */

package com.ibm.pross.server.channel;

/**
 * Interface for an atomic (synchronous) broadcast channel which is a necessary
 * building block of proactive security protocols
 */
public interface AtomicBroadcastChannel {

	/**
	 * Registers a ChannelListener with the channel to receive messages
	 * 
	 * @param channelListener
	 */
	public void register(final ChannelListener listener);

	/**
	 * Returns a SendContext which can be used to broadcast to the channel
	 *  
	 * @param senderId
	 */
	public ChannelSender link(final int senderId);
	
	/**
	 * Unregisters a ChannelListener with the channel (will no longer receive messages)
	 * 
	 * @param shareholder
	 */
	public void unregister(final ChannelListener listener);
}
