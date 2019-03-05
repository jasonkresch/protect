/*
 * Copyright (c) IBM Corporation 2018. All Rights Reserved.
 * Project name: pross
 * This project is licensed under the MIT License, see LICENSE.
 */

package com.ibm.pross.client.prf;

import java.math.BigInteger;

import com.ibm.pross.common.CommonConfiguration;
import com.ibm.pross.common.EcPseudoRandomFunction;
import com.ibm.pross.common.util.RandomNumberGenerator;
import com.ibm.pross.common.util.crypto.ecc.EcCurve;
import com.ibm.pross.common.util.crypto.ecc.EcPoint;

/**
 * Implements verifiable derivation
 */
public class VerifiedDerivation implements EcPseudoRandomFunction {

	// Static fields
	final public static EcCurve curve = CommonConfiguration.CURVE;
	final public static BigInteger r = curve.getR();

	// Private fields
	private final EcPseudoRandomFunction firstDerivation;
	private final EcPseudoRandomFunction secondDerivation;

	/**
	 * Constructs a verifiable derivation
	 * 
	 * Any call to derive will validate consistency between the results from both derivations.
	 * 
	 * @param firstDerivation
	 *            The first derivation is what is used to obtain the result from
	 *            the server. It may be the same as the second derivation or
	 *            different, for example the first one may be oblivious.
	 * @param secondDerivation
	 *            The second derivation is used to obtain the challenge
	 *            response, it may be identical to the first derivation.
	 */
	public VerifiedDerivation(final EcPseudoRandomFunction firstDerivation, final EcPseudoRandomFunction secondDerivation) {
		
		this.firstDerivation = firstDerivation;
		this.secondDerivation = secondDerivation;
		
		if (!this.firstDerivation.getPublicKey().equals(this.secondDerivation.getPublicKey()))
		{
			throw new IllegalArgumentException("The derivation's public keys do not match!");
		}
	}

	@Override
	public EcPoint derive(final EcPoint input) throws Exception {

		// Perform derivation
		final EcPoint result = this.firstDerivation.derive(input);

		// Form a challenge challenge
		final BigInteger v = RandomNumberGenerator.generateRandomPositiveInteger(r);
		final BigInteger w = RandomNumberGenerator.generateRandomPositiveInteger(r);
		final EcPoint challenge = ChallengeResponseVerifier.generateChallenge(input, v, w, curve);

		// Get response to challenge
		final EcPoint response = this.secondDerivation.derive(challenge);

		// Verify response consistency
		if (ChallengeResponseVerifier.isResponseValid(response, getPublicKey(), v, w, curve, result)) {
			return result;
		} else {
			throw new Exception("Invalid result obtained from server");
		}

	}

	@Override
	public EcPoint getPublicKey() {
		return this.firstDerivation.getPublicKey();
	}

}
