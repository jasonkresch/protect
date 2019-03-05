package com.ibm.pross.server.channel.bft;

import java.io.Serializable;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;

public class BftLog implements Serializable {

	private static final long serialVersionUID = 4660943197603171465L;

	private final List<byte[]> messageLog = Collections.synchronizedList(new LinkedList<byte[]>());
	
	public synchronized void addMessage(byte[] receivedMessage) {
		messageLog.add(receivedMessage);
	}
	
	public synchronized List<byte[]> getMessageLog() {
		return Collections.unmodifiableList(messageLog);
	}
	
}
