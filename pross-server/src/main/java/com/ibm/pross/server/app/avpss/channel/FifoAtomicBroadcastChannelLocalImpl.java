package com.ibm.pross.server.app.avpss.channel;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import com.ibm.pross.server.messages.Message;

public class FifoAtomicBroadcastChannelLocalImpl implements FifoAtomicBroadcastChannel {

	private final List<Message> messageLog = Collections.synchronizedList(new ArrayList<>());

	public synchronized void send(final Message message) {

		// Add message to message log
		messageLog.add(message);
		
		notifyAll();
	}

	public synchronized Message getMessage(final long messageIndex) {
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
