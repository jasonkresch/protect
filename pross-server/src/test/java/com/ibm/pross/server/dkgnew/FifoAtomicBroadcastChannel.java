package com.ibm.pross.server.dkgnew;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import com.ibm.pross.server.messages.Message;

public class FifoAtomicBroadcastChannel {

	private final List<DkgNewShareholder> registeredShareholders = new ArrayList<>();
	private final List<Message> messageLog = Collections.synchronizedList(new ArrayList<>());
	
	public synchronized void registerShareholder(final DkgNewShareholder shareholder) {
		this.registeredShareholders.add(shareholder);
	}

	public synchronized void broadcast(final Message message) {

		// Add message to message log
		messageLog.add(message);
		
		notifyAll();
	}

	public Message getMessage(int messageIndex) {
		return messageLog.get(messageIndex);
	}
	
	public int getMessageSize()
	{
		synchronized (this.messageLog)
		{
			return this.messageLog.size();
		}
	}

}
