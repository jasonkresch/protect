package com.ibm.pross.server.channel.bft;

import com.ibm.pross.server.channel.ChannelSender;
import com.ibm.pross.server.messages.SignedMessage;
import com.ibm.pross.server.util.MessageSerializer;

import bftsmart.tom.ServiceProxy;

public class BftChannelSender implements ChannelSender {

	private final ServiceProxy serviceProxy;

	public BftChannelSender(int senderId) {
		this.serviceProxy = new ServiceProxy(senderId);
	}

	@Override
	public void broadcast(SignedMessage message) {

		// Serialize message to bytes
		byte[] serializedMessage = MessageSerializer.serializeSignedMessage(message);

		// Send total ordered message
		//System.out.println("Sending message: " + HexUtil.binToHex(serializedMessage));
		this.serviceProxy.invokeOrdered(serializedMessage);

		// Give some time for everyone to process the message
		try {
			Thread.sleep(1000);
		} catch (InterruptedException e) {
			throw new RuntimeException("interrupted", e);
		}

	}

}
