/*
 * Copyright (c) IBM Corporation 2018. All Rights Reserved.
 * Project name: pross
 * This project is licensed under the MIT License, see LICENSE.
 */

package com.ibm.pross.server.messages;

import java.io.Serializable;

public class Payload implements Serializable {

	private static final long serialVersionUID = 5006028177758309022L;

	public enum OpCode {

		NA, // NA (e.g., for private paylods)

		/***** Distributed Key Generation *****/

		// DKG: Initial establishment of the secret (x)
		DKG_VSS, // Distributed key generation init
		DKG_ACCUSATIONS, // Accusations
		DKG_REBUTTAL, // Rebuttals

		/***** Proactive Secret Sharing *****/

		// PROSS: Refresh operation
		REFRESH_VSS, // Verifiable SS
		REFRESH_ACCUSATIONS, // Accusations
		REFRESH_REBUTTAL, // Rebuttals

		// PROSS: Reconstruction operation
		RECONSTRUCTION_DETECT_CORRUPT, // Detection
		RECONSTRUCTION_VSS, // Reconstruction VSS
		RECONSTRUCTION_ACCUSATIONS, // Accusations
		RECONSTRUCTION_REBUTTAL, // Rebuttals
		RECONSTRUCTION_CONTRIBUTION, // Contribution

		// PROSS: Dynamic rekey operation
		DYNAMIC_REKEY, // New public keys

		// NEW-DKG:
		MS, // Penderson Commitment and Shares
		VV, // Verification Vector
		RB, // Rebuttal
		ZK, // Zero Knowledge
		BP, // Bulk Proofs

		// AVSS
		PS, // Public Sharing
		BFT_CERTIFICATION; // Certification of message sent over BFT
	}

	private final OpCode opCode;
	private final Object data;

	public Payload(final OpCode opCode, final Object data) {
		this.opCode = opCode;
		this.data = data;
	}

	public OpCode getOpcode() {
		return this.opCode;
	}

	public Object getData() {
		return this.data;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((data == null) ? 0 : data.hashCode());
		result = prime * result + ((opCode == null) ? 0 : opCode.hashCode());
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
		Payload other = (Payload) obj;
		if (data == null) {
			if (other.data != null)
				return false;
		} else if (!data.equals(other.data))
			return false;
		if (opCode != other.opCode)
			return false;
		return true;
	}

	@Override
	public String toString() {
		return "Payload [opCode=" + opCode + ", data=" + data + "]";
	}

}
