/*
 * Copyright (c) IBM Corporation 2018. All Rights Reserved.
 * Project name: pross
 * This project is licensed under the MIT License, see LICENSE.
 */

package com.ibm.pross.server.shareholder;

import java.math.BigInteger;
import java.security.PrivateKey;

import com.ibm.pross.common.util.crypto.ecc.EcPoint;
import com.ibm.pross.common.util.shamir.Shamir;
import com.ibm.pross.common.util.shamir.ShamirShare;
import com.ibm.pross.server.Administration.Configuration;
import com.ibm.pross.server.Channel;
import com.ibm.pross.server.Clock;

public class FaultyShareholder extends Shareholder {

	/**
	 * Implements a shareholder which can suffer faults and misbehave. This can
	 * be used to test functionality and correctness in the face of errors
	 * 
	 * @param channel
	 * @param clock
	 * @param index
	 * @param configuration
	 */
	public FaultyShareholder(Channel channel, Clock clock, int index, Configuration configuration) {
		super(channel, clock, index, configuration);
	}

	/////////////
	// Attacks //
	/////////////

	protected void crash() {
		// Lose all state

	}

	/**
	 * Stop processing messages altogether
	 */
	protected void freeze() {
		this.channel.unregister(this);
	}

	/**
	 * Begin processing messages again
	 */
	protected void unfreeze() {
		this.channel.unregister(this);
	}

	/**
	 * Process messages, but stop sending them
	 */
	protected void mute() {
		throw new RuntimeException("not implemented");
	}

	/**
	 * Send messages signed using the provided signing key
	 */
	protected void impersonate(final PrivateKey newSigningKey) {
		throw new RuntimeException("not implemented");
	}

	/**
	 * Send messages encrypted with invalid keys
	 */
	protected void corruptEncryption(final boolean corruptEncryption) {
		throw new RuntimeException("not implemented");
	}

	/**
	 * Corrupts the x-coordinate of our share
	 */
	protected void corruptShareX() {
		this.share = new ShamirShare(this.share.getX().add(BigInteger.ONE), this.share.getY());
	}

	/**
	 * Corrupts the y-coordinate of our share
	 */
	protected void corruptShareY() {
		this.share = new ShamirShare(this.share.getX(), this.share.getY().add(BigInteger.ONE));
	}

	/**
	 * Corrupts our share public keys (triggers detection for repair)
	 */
	protected void corruptSharePublicKeys() {
		final BigInteger[] coefficients = Shamir.generateCoefficients(this.configuration.getThreshold());
		final EcPoint[] feldmanValues = Shamir.generateFeldmanValues(coefficients);
		this.sharePublicKeys = Shamir.computeSharePublicKeys(feldmanValues, this.configuration.getN());
	}

	/**
	 * Make false accusations during reconstruction phase
	 */
	protected void accuseReconstruct() {
		throw new RuntimeException("not implemented");
	}

	/**
	 * Send corrupted share contribution during reconstruction phase
	 */
	protected void sendCorruptShareContribution() {
		throw new RuntimeException("not implemented");
	}

	/**
	 * Make false accusations during refresh
	 */
	protected void accuseRefresh() {
		throw new RuntimeException("not implemented");
	}

	/**
	 * Send duplicate messages for everything
	 */
	protected void babble() {
		throw new RuntimeException("not implemented");
	}

	/**
	 * Fix everything wrong with this server
	 */
	protected void clear() {
		// Restore state to uncompromised server
	}

}
