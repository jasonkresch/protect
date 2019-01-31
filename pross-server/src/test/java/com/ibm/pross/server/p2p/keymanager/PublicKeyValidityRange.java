package com.ibm.pross.server.p2p.keymanager;

import java.security.PublicKey;

import com.ibm.pross.server.p2p.messages.Message;

public class PublicKeyValidityRange {

	private final long senderId;
	private final PublicKey publicKey;

	private final long minValidMessageId;
	private final long maxValidMessageId;

	public PublicKeyValidityRange(final long senderId, final PublicKey publicKey, final long minValidMessageId,
			final long maxValidMessageId) {
		this.senderId = senderId;
		this.publicKey = publicKey;
		this.minValidMessageId = minValidMessageId;
		this.maxValidMessageId = maxValidMessageId;
	}


	
}
