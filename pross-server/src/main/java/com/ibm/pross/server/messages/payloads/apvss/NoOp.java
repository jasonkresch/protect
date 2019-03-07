package com.ibm.pross.server.messages.payloads.apvss;

import com.ibm.pross.server.messages.Payload;

/**
 * Used when we have lost our share but need to send something to advance the
 * protocol
 */
public class NoOp extends Payload {

	public NoOp() {
		super(OpCode.NOOP, new String("NO OP"));
	}

	@Override
	public String toString() {
		return "NoOp";
	}
}