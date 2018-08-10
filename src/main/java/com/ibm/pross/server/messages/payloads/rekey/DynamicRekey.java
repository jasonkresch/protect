/*
 * Copyright (c) IBM Corporation 2018. All Rights Reserved.
 * Project name: pross
 * This project is licensed under the MIT License, see LICENSE.
 */

package com.ibm.pross.server.messages.payloads.rekey;

import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECPoint;

import com.ibm.pross.common.util.crypto.ecc.EcPoint;
import com.ibm.pross.server.messages.Payload;

public class DynamicRekey implements Payload {

	private static final long serialVersionUID = 1710761352037203847L;

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

}
