package com.ibm.pross.server.p2p.channel.links;

import java.util.Collections;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import com.ibm.pross.server.p2p.messages.Message;
import com.ibm.pross.server.p2p.messages.MessagePayload;

public class PerfectLink extends StubbornLink {

	private final Set<Message> receivedMessages = Collections.newSetFromMap(new ConcurrentHashMap<Message, Boolean>());

	public PerfectLink() {
		super();
	}

	@Override
	public void deliver(final Message message) {
		// Ensure no duplicate messages are delivered
		synchronized (this.receivedMessages) {
			if (!receivedMessages.contains(message)) {
				receivedMessages.add(message);
				this.deliverOnce(message);
			}
		}
	}

	public void deliverOnce(final Message message) {
		System.out.println("Received unique message: " + message);
	}

	public static void main(final String args[]) throws Exception {
		
		final int senderId = 2000;
		final PerfectLink link = new PerfectLink();

		final Message msg1 = new Message(senderId, 456, 1, new MessagePayload("hello"), null);
		link.repeatSendAttempt(msg1);

		final Message msg2 = new Message(senderId, 456, 2, new MessagePayload("hi"), null);
		link.repeatSendAttempt(msg2);

		final Message msg3 = new Message(senderId, 678, 3, new MessagePayload("hey"), null);
		link.repeatSendAttempt(msg3);

		// Stay alive
		Thread.sleep(RESEND_DELAY * 2);

		final Message msg4 = new Message(senderId, 678, 4, new MessagePayload("good morning"), null);
		link.repeatSendAttempt(msg4);

		final Message msg5 = new Message(senderId, 678, 5, new MessagePayload("good evening"), null);
		link.repeatSendAttempt(msg5);

		// Stay alive
		Thread.sleep(RESEND_DELAY * 5);
	}
}
