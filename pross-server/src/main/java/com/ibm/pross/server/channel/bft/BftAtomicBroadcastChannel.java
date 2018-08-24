package com.ibm.pross.server.channel.bft;

import com.ibm.pross.server.channel.AtomicBroadcastChannel;
import com.ibm.pross.server.channel.ChannelListener;
import com.ibm.pross.server.channel.ChannelSender;

public class BftAtomicBroadcastChannel implements AtomicBroadcastChannel {

	@Override
	public void register(final ChannelListener listener) {

		final Thread thread = new Thread() {
			public void run() {
				// Start BFT Service Instance to relay messages to the listener
				new BftListenerWrapper(listener);
			}
		};

		thread.start();
	}

	@Override
	public ChannelSender link(final int senderId) {
		return new BftChannelSender(senderId);
	}

	@Override
	public void unregister(final ChannelListener listener) {
		throw new RuntimeException("not implemented");
	}

}
