package com.ibm.pross.server.p2p.messages;

import java.io.Serializable;

public class MessagePayload implements Serializable {

	private static final long serialVersionUID = -2783726805821216545L;

	private final String payload;

	public MessagePayload(String payload) {
		this.payload = payload;
	}

	public String getPayload() {
		return payload;
	}

	@Override
	public String toString() {
		return "MessagePayload [payload=" + payload + "]";
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((payload == null) ? 0 : payload.hashCode());
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
		MessagePayload other = (MessagePayload) obj;
		if (payload == null) {
			if (other.payload != null)
				return false;
		} else if (!payload.equals(other.payload))
			return false;
		return true;
	}

}
