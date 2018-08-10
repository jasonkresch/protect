/*
 * Copyright (c) IBM Corporation 2018. All Rights Reserved.
 * Project name: pross
 * This project is licensed under the MIT License, see LICENSE.
 */

package com.ibm.pross.server;

import java.math.BigInteger;
import java.security.PublicKey;
import java.security.Security;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import com.ibm.pross.client.PrfClient;
import com.ibm.pross.client.prf.DerivationFactory;
import com.ibm.pross.common.CommonConfiguration;
import com.ibm.pross.common.PseudoRandomFunction;
import com.ibm.pross.common.util.crypto.ecc.EcCurve;
import com.ibm.pross.common.util.crypto.ecc.EcPoint;
import com.ibm.pross.server.shareholder.Shareholder;

/**
 * Performs all trusted administrative functions on the shareholders
 * 
 * @author jresch
 *
 */
public class Administration {

	// Static fields
	final public static EcCurve curve = CommonConfiguration.CURVE;
	final public static BigInteger r = curve.getR();
	final public static EcPoint G = curve.getG();

	/**
	 * Configuration is only writable by Administration, but is passed to each
	 * Shareholder as well as to the Coordinator.
	 */
	public final class Configuration {

		private final int n;
		private final int threshold;
		private final int updateThreshold;

		public Configuration(final int n, final int threshold, final int updateThreshold) {
			this.n = n;
			this.threshold = threshold;
			this.updateThreshold = updateThreshold;
		}

		public int getN() {
			return n;
		}

		public int getThreshold() {
			return threshold;
		}

		public int getUpdateThreshold() {
			return updateThreshold;
		}

		public List<PublicKey> getEncryptionPublicKeys() {
			return Administration.this.getShareholderEncryptionKeys();
		}

		public List<PublicKey> getVerifyingPublicKeys() {
			return Administration.this.getShareholderVerifyingKeys();
		}

	}

	static {
		Security.addProvider(new BouncyCastleProvider());
	}

	// Our state
	private final Configuration configuration;
	private final Clock clock;
	private final Channel channel;
	private final Shareholder[] shareholders;
	private final Coordinator coordinator;

	private final List<PublicKey> shareholderEncryptionKeys = new ArrayList<>();
	private final List<PublicKey> shareholderVerifyingKeys = new ArrayList<>();

	public Administration(int n, int threshold, int updateThreshold) {

		// Set threshold parameters
		this.configuration = new Configuration(n, threshold, updateThreshold);

		// Create synchronous channel
		this.channel = new Channel();

		// Create global clock
		this.clock = new Clock();

		// Create shareholders
		this.shareholders = new Shareholder[n];
		for (int i = 0; i < n; i++) {

			final Shareholder shareholder = new Shareholder(this.channel, this.clock, i, configuration);

			// Provision keys to other shareholders
			this.shareholderEncryptionKeys.add(shareholder.getEncryptionPublicKey());
			this.shareholderVerifyingKeys.add(shareholder.getVerifyingPublicKey());

			this.shareholders[i] = shareholder;
		}

		// Now that all keys are generated, provision them
		for (final Shareholder shareholder : this.shareholders) {
			shareholder.updateKeysFromConfiguration();
		}

		this.coordinator = new Coordinator(shareholders, clock);
		this.coordinator.performDistributedKeyGeneration();

	}

	public List<PublicKey> getShareholderEncryptionKeys() {
		return Collections.unmodifiableList(this.shareholderEncryptionKeys);
	}

	public List<PublicKey> getShareholderVerifyingKeys() {
		return Collections.unmodifiableList(this.shareholderVerifyingKeys);
	}

	public Coordinator getCoordinator() {
		return this.coordinator;
	}

	/**
	 * Provisions a new client that can perform T-OPRF operations against the
	 * shareholders
	 * 
	 * @return A new instance of a KeyDerivationClient which uses these
	 *         shareholders
	 */
	public PrfClient provisionClient() {

		// Setup derivations appropriately to use T-OPRF, Obliviousness, and
		// Verifiability
		final PseudoRandomFunction derivation = DerivationFactory
				.createVerifiedObliviousRobustThresholdDerivation(this.shareholders, configuration.getThreshold());
		final PrfClient client = new PrfClient(derivation);
		return client;
	}

	public void resetShareholder(int shareholderIndex) {
		// Reset a server (blank state, new keys)

		// Provision new public keys

		// New instance, same index as others. Swap it in place for the others.
		// Register it with the same broadcast channel
	}

	public void redefineThreshold(int newThrehsold) {
		// Define new threshold

		// Update all shares accordingly
	}

	public void redefineUpdateThreshold(int newThrehsold) {
		// Set new update threshold, if it is within the valid range between t
		// and n
	}

	public void redefineNumShareholders(int n) {
		// Set new n, add or remove shareholders as necessary
	}

}
