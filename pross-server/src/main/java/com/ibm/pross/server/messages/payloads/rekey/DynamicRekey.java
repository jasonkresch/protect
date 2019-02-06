/*
 * Copyright (c) IBM Corporation 2018. All Rights Reserved.
 * Project name: pross
 * This project is licensed under the MIT License, see LICENSE.
 */

package com.ibm.pross.server.messages.payloads.rekey;

import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECPoint;
import java.util.UUID;

import com.ibm.pross.common.util.crypto.ecc.EcPoint;
import com.ibm.pross.server.messages.Payload;

public class DynamicRekey extends Payload {

	private static final long serialVersionUID = 1710761352037203847L;

	// FIXME: Remove this when set hashcode and equality are fixed
	private final UUID messageId = UUID.randomUUID();
	
	private final long updateTime;

	private final PublicKey newVerifyingKey;
	private final PublicKey newEncryptionKey;

	public DynamicRekey(final long timePeriod, final PublicKey newVerifyingKey, final PublicKey newEncryptionKey) {
		this.updateTime = timePeriod;
		this.newVerifyingKey = newVerifyingKey;
		this.newEncryptionKey = newEncryptionKey;
	}

	@Override
	public OpCode getOpcode() {
		return OpCode.DYNAMIC_REKEY;
	}

	public long getUpdateTime() {
		return updateTime;
	}

	public PublicKey getNewVerifyingKey() {
		return newVerifyingKey;
	}

	public PublicKey getNewEncryptionKey() {
		return newEncryptionKey;
	}

	private static String keyToString(PublicKey key) {
		final ECPublicKey ecPublicKey = (ECPublicKey) key;
		final ECPoint javaPoint = ecPublicKey.getW();
		final EcPoint point = new EcPoint(javaPoint.getAffineX(), javaPoint.getAffineY());
		return point.toString();
	}

	@Override
	public String toString() {
		return "DynamicRekey [updateTime=" + updateTime + ", newVerifyingKey=" + keyToString(newVerifyingKey)
				+ ", newEncryptionKey=" + keyToString(newEncryptionKey) + "]";
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((messageId == null) ? 0 : messageId.hashCode());
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
		DynamicRekey other = (DynamicRekey) obj;
		if (messageId == null) {
			if (other.messageId != null)
				return false;
		} else if (!messageId.equals(other.messageId))
			return false;
		return true;
	}



	
}
