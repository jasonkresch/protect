/*
 * Copyright (c) IBM Corporation 2018. All Rights Reserved.
 * Project name: pross
 * This project is licensed under the MIT License, see LICENSE.
 */

package com.ibm.pross.server.shareholder.state;

import java.security.KeyPair;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

import com.ibm.pross.common.util.crypto.EcKeyGeneration;
import com.ibm.pross.server.messages.payloads.rekey.DynamicRekey;
import com.ibm.pross.server.shareholder.Shareholder;

public class RekeyingStateTracker {

	// Attributes related to rekeying
	final private long timePeriod;
	final private Shareholder shareholder;
	final private int n;

	// Set of servers we have received values from
	private final ConcurrentMap<Integer, DynamicRekey> receivedRekeyings;

	// Set of servers we have identified as malfunctioning or compromised or who
	// didn't send an update, or sent two updates, or sent an invalid update
	private final Set<Integer> malfunctioningShareholders;

	// New key pairs
	private final KeyPair newSigningKeyPair;
	private final KeyPair newDecryptionKeyPair;

	enum States {
		INITALIZED, SENT_REKEY, IDENTIFIED_ERRORS;
	}

	private volatile States currentState;

	public RekeyingStateTracker(long timePeriod, final Shareholder shareholder, final int n) {

		this.timePeriod = timePeriod;
		this.shareholder = shareholder;
		this.n = n;

		this.receivedRekeyings = new ConcurrentHashMap<>();
		this.malfunctioningShareholders = new HashSet<>();

		this.currentState = States.INITALIZED;

		// Generate new key pairs
		this.newSigningKeyPair = EcKeyGeneration.generateKeyPair();
		this.newDecryptionKeyPair = EcKeyGeneration.generateKeyPair();
	}

	public KeyPair getSigningKeyPair() {
		return this.newSigningKeyPair;
	}

	public KeyPair getDecryptionKeyPair() {
		return this.newDecryptionKeyPair;
	}

	public synchronized void sendRekeyMessage() {
		if (this.currentState == States.INITALIZED) {

			final DynamicRekey rekeyPayload = new DynamicRekey(timePeriod, this.newSigningKeyPair.getPublic(),
					this.newDecryptionKeyPair.getPublic());

			this.shareholder.sendPublicMessage(rekeyPayload);

			this.currentState = States.SENT_REKEY;

		} else {
			throw new IllegalStateException("Must be in States.INITIALIZED");
		}
	}

	public void saveKeyUpdate(final int sender, final DynamicRekey rekeyPayload) {

		if (!(this.currentState.equals(States.SENT_REKEY) || this.currentState.equals(States.INITALIZED))) {
			throw new IllegalStateException("Must be in States.SENT_REKEY or States.INITIALIZED");
		}

		// Make sure time period is correct (this should already be checked)
		if (rekeyPayload.getUpdateTime() != this.timePeriod) {
			throw new RuntimeException("Should not have gotten to this state");
		}

		// Make sure both keys are valid EC public keys
		if (!(rekeyPayload.getNewEncryptionKey() instanceof ECPublicKey)) {
			this.malfunctioningShareholders.add(sender);
			System.err.println("Received invalid encryption key");
			return;
		}

		if (!(rekeyPayload.getNewVerifyingKey() instanceof ECPublicKey)) {
			this.malfunctioningShareholders.add(sender);
			System.err.println("Received invalid verifying key");
			return;
		}

		// Make sure keys are not equal to each other
		if (rekeyPayload.getNewEncryptionKey().equals(rekeyPayload.getNewVerifyingKey())) {
			this.malfunctioningShareholders.add(sender);
			System.err.println("Received identical encryption and verifying keys");
			return;
		}

		// Key appears valid, make sure it is not a duplicate
		final DynamicRekey previous = this.receivedRekeyings.putIfAbsent(sender, rekeyPayload);
		if (previous != null) {
			// Received duplicate messages, mark as malfunctioning
			this.malfunctioningShareholders.add(sender);
		}
	}

	public synchronized void determineMalfunctioningShareholders() {

		if (this.currentState == States.SENT_REKEY) {

			this.currentState = States.IDENTIFIED_ERRORS;

			final Set<Integer> missingUpdates = new HashSet<>();

			// Identify missing shareholders
			for (int i = 0; i < this.n; i++) {
				if (!this.receivedRekeyings.containsKey(i)) {
					missingUpdates.add(i);
				}
			}

			this.malfunctioningShareholders.addAll(missingUpdates);

		} else {
			throw new IllegalStateException("Must be in States.SENT_REKEY");
		}
	}

	public void updateKeys(final PublicKey[] verifyingKeys, final PublicKey[] encryptionKeys) {
		if (this.currentState == States.IDENTIFIED_ERRORS) {

			// Update keys for each non-malfunctioning shareholder
			for (final Integer shareholder : this.receivedRekeyings.keySet()) {
				if (!this.malfunctioningShareholders.contains(shareholder)) {

					final DynamicRekey rekeyPayload = this.receivedRekeyings.get(shareholder);
					verifyingKeys[shareholder] = rekeyPayload.getNewVerifyingKey();
					encryptionKeys[shareholder] = rekeyPayload.getNewEncryptionKey();
					
				}
			}

		} else {
			throw new IllegalStateException("Must be in States.IDENTIFIED_ERRORS");
		}
	}

	public Set<Integer> getMalfunctioningShareholders() {
		if (this.currentState == States.IDENTIFIED_ERRORS) {
			return Collections.unmodifiableSet(this.malfunctioningShareholders);
		} else {
			throw new IllegalStateException("Must be in States.IDENTIFIED_ERRORS");
		}
	}

}
