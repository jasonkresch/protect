package com.ibm.pross.server.app.avpss.channel;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import com.ibm.pross.server.messages.PublicMessage;

public class FifoAtomicBroadcastChannelLocalImpl implements FifoAtomicBroadcastChannel {

	private final List<PublicMessage> messageLog = Collections.synchronizedList(new ArrayList<>());

	public synchronized void send(final PublicMessage message) {

		// Add message to message log
		messageLog.add(message);
		
		notifyAll();
	}

	public synchronized PublicMessage getMessage(final long messageIndex) {
		return messageLog.get((int) messageIndex);
	}
	
	public synchronized int getMessageCount()
	{
		synchronized (this.messageLog)
		{
			return this.messageLog.size();
		}
	}

}
