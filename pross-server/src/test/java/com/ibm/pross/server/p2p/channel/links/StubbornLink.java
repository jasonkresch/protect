package com.ibm.pross.server.p2p.channel.links;

import java.util.Timer;
import java.util.TimerTask;
import java.util.concurrent.ConcurrentLinkedQueue;

import com.ibm.pross.server.p2p.messages.Message;
import com.ibm.pross.server.p2p.messages.MessagePayload;

public class StubbornLink extends FairLossLink {

	public static final int RESEND_DELAY = 3000; // 3 seconds

	private final ConcurrentLinkedQueue<Message> repeatSendQueue = new ConcurrentLinkedQueue<>();
	private final Timer timer = new Timer(true);

	public StubbornLink() {
		super();

		// Schedule timer to periodically resend every message previously sent
		this.timer.scheduleAtFixedRate(new TimerTask() {
			@Override
			public void run() {
				System.out.println("Attempting to resend: " + repeatSendQueue.size() + " messages...");
				for (final Message msg : StubbornLink.this.repeatSendQueue) {
					StubbornLink.this.attemptSend(msg);
				}
			}
		}, RESEND_DELAY, RESEND_DELAY);
	}

	/**
	 * Will continue to attempt delivery of the message forever. When using a
	 * FairLossLink underneath, this guarantees the message will eventually be
	 * delivered.
	 * 
	 * @param recipientIdentifier
	 *            The unique if of the recipient of the message
	 * @param message
	 *            The message to attempt to deliver repeatedly to the intended
	 *            recipient
	 */
	public void repeatSendAttempt(final Message message) {
		super.attemptSend(message);
		repeatSendQueue.add(message);
	}

	public static void main(final String args[]) throws Exception {

		final int senderId = 100;
		final StubbornLink link = new StubbornLink();

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
