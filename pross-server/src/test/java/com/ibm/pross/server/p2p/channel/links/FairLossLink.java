package com.ibm.pross.server.p2p.channel.links;

import com.ibm.pross.server.p2p.messages.Message;
import com.ibm.pross.server.p2p.messages.MessagePayload;

public class FairLossLink {

	public FairLossLink() {

	}

	/**
	 * Attempts to deliver the message. The only contract is that the probability
	 * that the message is delivered to the recipient must be greater than zero.
	 * 
	 * @param recipientIdentifier
	 *            The unique if of the recipient of the message
	 * @param message
	 *            The message to attempt to deliver to the intended recipient
	 */
	public void attemptSend(final Message message) {
		System.out.println("Attempting to deliver message to: " + message.getRecipientId());
		if (Math.random() < 0.5) {
			deliver(message);
		} else {
			System.out.println("Delivery failed");
		}
	}

	/**
	 * Delivers a received message. The same message may be delivered multiple
	 * times. This event must be invoked by the implementation whenever a message is
	 * properly received.
	 * 
	 * @param senderIdentifier
	 *            The unique id of the sender of the message
	 * @param message
	 *            The message to attempt to deliver to the intended recipient
	 */
	public void deliver(final Message message) {
		System.out.println("Received message: " + message.toString());
	}

	public static void main(final String args[]) throws Exception {
		final int senderId = 123;
		final FairLossLink link = new FairLossLink();

		final Message msg1 = new Message(senderId, 456, 1, new MessagePayload("hello"), null);
		link.attemptSend(msg1);

		final Message msg2 = new Message(senderId, 456, 2, new MessagePayload("hi"), null);
		link.attemptSend(msg2);

		final Message msg3 = new Message(senderId, 678, 3, new MessagePayload("hey"), null);
		link.attemptSend(msg3);
	}
}
