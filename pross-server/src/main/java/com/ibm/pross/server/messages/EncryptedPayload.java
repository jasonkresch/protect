/*
 * Copyright (c) IBM Corporation 2018. All Rights Reserved.
 * Project name: pross
 * This project is licensed under the MIT License, see LICENSE.
 */

package com.ibm.pross.server.messages;

import java.io.Serializable;
import java.util.Arrays;

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

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((algorithm == null) ? 0 : algorithm.hashCode());
		result = prime * result + Arrays.hashCode(encryptedBytes);
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
		EncryptedPayload other = (EncryptedPayload) obj;
		if (algorithm == null) {
			if (other.algorithm != null)
				return false;
		} else if (!algorithm.equals(other.algorithm))
			return false;
		if (!Arrays.equals(encryptedBytes, other.encryptedBytes))
			return false;
		return true;
	}

	
	
}
