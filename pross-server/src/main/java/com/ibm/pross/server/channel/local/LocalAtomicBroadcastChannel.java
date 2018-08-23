/*
 * Copyright (c) IBM Corporation 2018. All Rights Reserved.
 * Project name: pross
 * This project is licensed under the MIT License, see LICENSE.
 */

package com.ibm.pross.server.channel.local;

import java.util.ArrayList;
import java.util.List;

import com.ibm.pross.server.channel.AtomicBroadcastChannel;
import com.ibm.pross.server.channel.ChannelListener;
import com.ibm.pross.server.channel.ChannelSender;

/**
 * Implements a synchronous broadcast channel which is a necessary building
 * block of proactive security
 */
public class LocalAtomicBroadcastChannel implements AtomicBroadcastChannel {

	private final List<ChannelListener> registeredListeners = new ArrayList<>();

	/**
	 * Registers a shareholder with the channel to receive messages
	 * 
	 * @param shareholder
	 */
	@Override
	public void register(final ChannelListener listener) {
		synchronized (this.registeredListeners) {
			this.registeredListeners.add(listener);
		}
	}

	/**
	 * Unregisters a shareholder with the channel (will no longer receive messages)
	 * 
	 * @param shareholder
	 */
	@Override
	public void unregister(final ChannelListener listener) {
		synchronized (this.registeredListeners) {
			this.registeredListeners.remove(listener);
		}
	}

	@Override
	public ChannelSender link(int senderId) {
		return new LocalChannelSender(registeredListeners);
	}

}
