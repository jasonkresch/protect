/*
 * Copyright (c) IBM Corporation 2018. All Rights Reserved.
 * Project name: pross
 * This project is licensed under the MIT License, see LICENSE.
 */

package com.ibm.pross.server.messages;

public class Payload  {

	public enum OpCode {
		// AVSS
		PS, // Public Sharing
		ZK, // Zero Knowledge
		NOOP, // No-Op
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
