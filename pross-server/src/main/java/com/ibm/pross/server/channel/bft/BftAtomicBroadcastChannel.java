package com.ibm.pross.server.channel.bft;

import com.ibm.pross.server.channel.AtomicBroadcastChannel;
import com.ibm.pross.server.channel.ChannelListener;
import com.ibm.pross.server.channel.ChannelSender;

public class BftAtomicBroadcastChannel implements AtomicBroadcastChannel {

	private volatile BftListenerWrapper wrapper;
	
	@Override
	public void register(final ChannelListener listener) {
		this.wrapper = new BftListenerWrapper(listener);
	}
	
	public boolean isReady()
	{
		return ((this.wrapper != null) && (this.wrapper.isReady()));
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
