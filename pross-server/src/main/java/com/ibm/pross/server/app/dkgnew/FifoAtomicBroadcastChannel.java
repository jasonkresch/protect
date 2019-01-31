package com.ibm.pross.server.app.dkgnew;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import com.ibm.pross.server.messages.Message;

public class FifoAtomicBroadcastChannel {

	private final List<Message> messageLog = Collections.synchronizedList(new ArrayList<>());


	public synchronized void broadcast(final Message message) {

		// Add message to message log
		messageLog.add(message);
		
		notifyAll();
	}

	public Message getMessage(int messageIndex) {
		return messageLog.get(messageIndex);
	}
	
	public int getMessageCount()
	{
		synchronized (this.messageLog)
		{
			return this.messageLog.size();
		}
	}

}
