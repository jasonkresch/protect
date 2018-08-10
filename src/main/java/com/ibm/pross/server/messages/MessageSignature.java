/*
 * Copyright (c) IBM Corporation 2018. All Rights Reserved.
 * Project name: pross
 * This project is licensed under the MIT License, see LICENSE.
 */

package com.ibm.pross.server.messages;

import java.io.Serializable;

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

}
