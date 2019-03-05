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


public class ObliviousDerivation implements EcPseudoRandomFunction {

	// Static fields
	final public static EcCurve curve = CommonConfiguration.CURVE;
	final public static BigInteger r = curve.getR();

	private final EcPseudoRandomFunction derivation;

	public ObliviousDerivation(final EcPseudoRandomFunction derivation) {
		this.derivation = derivation;
	}

	/**
	 * Implements derivation with localized blinding to protect secrecy of the
	 * input and output.
	 * 
	 * @throws Exception 
	 */
	@Override
	public EcPoint derive(final EcPoint input) throws Exception {

		// Generate blinding factor
		final BigInteger blindingFactor = RandomNumberGenerator.generateRandomPositiveInteger(r);

		// Blind the input
		final EcPoint blindedInput = curve.multiply(input, blindingFactor);

		// Perform derivation on blinded input
		final EcPoint blindedResult = this.derivation.derive(blindedInput);

		// Divide out blinding factor and return the result
		final BigInteger inverseBlindingFactor = blindingFactor.modInverse(r);
		return curve.multiply(blindedResult, inverseBlindingFactor);
		
	}

	@Override
	public EcPoint getPublicKey() {
		return this.derivation.getPublicKey();
	}

}
