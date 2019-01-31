/*
 * Copyright (c) IBM Corporation 2018. All Rights Reserved.
 * Project name: pross
 * This project is licensed under the MIT License, see LICENSE.
 */

package com.ibm.pross.server.messages;

import java.io.Serializable;
import java.util.Arrays;

/**
 * Represents the serialization of a digital signature which accompanies a
 * message to form a signed message
 */
public class MessageSignature implements Serializable {

	private static final long serialVersionUID = 2257106126137559366L;

	private final String algorithm;
	private final byte[] signatureBytes;

	public MessageSignature(final byte[] signatureBytes, final String algorithm) {
		this.algorithm = algorithm;
		this.signatureBytes = signatureBytes;
	}

	public String getAlgorithm() {
		return algorithm;
	}

	public byte[] getSignatureBytes() {
		return signatureBytes;
	}

	@Override
	public String toString() {
		return "[MessageSignature]";
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((algorithm == null) ? 0 : algorithm.hashCode());
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
		MessageSignature other = (MessageSignature) obj;
		if (algorithm == null) {
			if (other.algorithm != null)
				return false;
		} else if (!algorithm.equals(other.algorithm))
			return false;
		return true;
	}

	
}
