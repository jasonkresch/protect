/*
 * Copyright (c) IBM Corporation 2018. All Rights Reserved.
 * Project name: pross
 * This project is licensed under the MIT License, see LICENSE.
 */

package com.ibm.pross.server.messages.payloads.dkg;

import java.util.Set;
import java.util.SortedSet;

import com.ibm.pross.server.messages.Payload;

public class GenerationAccusations implements Payload {

	private static final long serialVersionUID = -6891010695262747471L;
	
	private final SortedSet<Integer> accused;

	public GenerationAccusations(final SortedSet<Integer> accused) {
		this.accused = accused;
	}

	@Override
	public OpCode getOpcode() {
		return OpCode.DKG_ACCUSATIONS;
	}

	public Set<Integer> getAccused() {
		return accused;
	}

	@Override
	public String toString() {
		return "GenerationAccusations [accused=" + accused + "]";
	}

}
