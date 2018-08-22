/*
 * Copyright (c) IBM Corporation 2018. All Rights Reserved.
 * Project name: pross
 * This project is licensed under the MIT License, see LICENSE.
 */

package com.ibm.pross.server.messages;

import java.io.Serializable;

/**
 * Represents the encryption of a content object
 */
public class EncryptedPayload implements Serializable {

	private static final long serialVersionUID = 7698538419680907496L;

	// This is used to support "rebuttles" by disclosing the plaintext value of what was encrypted
	// under the recipients public key. This is not serialized over the wire so no one except the sender 
	// should ever set it.
	public transient byte[] rebuttalEvidence;
	
	private final String algorithm;
	private final byte[] encryptedBytes;

	public EncryptedPayload(final byte[] encryptedBytes, final String algorithm) {
		this.algorithm = algorithm;
		this.encryptedBytes = encryptedBytes;
	}

	public String getAlgorithm() {
		return algorithm;
	}

	public byte[] getEncryptedBytes() {
		return encryptedBytes.clone();
	}

}
