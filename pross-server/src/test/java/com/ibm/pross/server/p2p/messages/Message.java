package com.ibm.pross.server.p2p.messages;

import java.io.Serializable;

public class Message implements Serializable {

	private static final long serialVersionUID = -7854754292257931612L;

	private final long senderId;
	private final long recipientId;
	private final long messageId;

	private final MessagePayload payload;
	private final MessageSignature signature;

	public Message(long senderId, long recipientId, long messageId, MessagePayload payload,
			MessageSignature signature) {
		this.senderId = senderId;
		this.recipientId = recipientId;
		this.messageId = messageId;
		this.payload = payload;
		this.signature = signature;
	}

	public long getSenderId() {
		return senderId;
	}

	public long getRecipientId() {
		return recipientId;
	}

	public long getMessageId() {
		return messageId;
	}

	public MessagePayload getPayload() {
		return payload;
	}

	public MessageSignature getSignature() {
		return signature;
	}

	@Override
	public String toString() {
		return "Message [senderId=" + senderId + ", recipientId=" + recipientId + ", messageId=" + messageId
				+ ", payload=" + payload + ", signature=" + signature + "]";
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + (int) (messageId ^ (messageId >>> 32));
		result = prime * result + ((payload == null) ? 0 : payload.hashCode());
		result = prime * result + (int) (recipientId ^ (recipientId >>> 32));
		result = prime * result + (int) (senderId ^ (senderId >>> 32));
		result = prime * result + ((signature == null) ? 0 : signature.hashCode());
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		Message other = (Message) obj;
		if (messageId != other.messageId)
			return false;
		if (payload == null) {
			if (other.payload != null)
				return false;
		} else if (!payload.equals(other.payload))
			return false;
		if (recipientId != other.recipientId)
			return false;
		if (senderId != other.senderId)
			return false;
		if (signature == null) {
			if (other.signature != null)
				return false;
		} else if (!signature.equals(other.signature))
			return false;
		return true;
	}

}
