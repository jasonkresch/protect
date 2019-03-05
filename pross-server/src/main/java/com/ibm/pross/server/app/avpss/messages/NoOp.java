package com.ibm.pross.server.app.avpss.messages;

import java.io.Serializable;

import com.ibm.pross.server.messages.Payload;

/**
 * Used when we have lost our share but need to send something to advance the
 * protocol
 */
public class NoOp extends Payload implements Serializable {

	private static final long serialVersionUID = 7765671719128090950L;

	public NoOp() {
		super(OpCode.NOOP, new Object());
	}

	@Override
	public String toString() {
		return "NoOp";
	}
}