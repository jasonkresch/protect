/*
 * Copyright (c) IBM Corporation 2018. All Rights Reserved.
 * Project name: pross
 * This project is licensed under the MIT License, see LICENSE.
 */

package com.ibm.pross.client.prf;

import java.math.BigInteger;

import com.ibm.pross.common.EcPseudoRandomFunction;
import com.ibm.pross.common.config.CommonConfiguration;
import com.ibm.pross.common.util.crypto.ecc.EcCurve;
import com.ibm.pross.common.util.crypto.ecc.EcPoint;

public class BasicDerivation implements EcPseudoRandomFunction {

	// Static fields
	final public static EcCurve curve = CommonConfiguration.CURVE;
	final public static BigInteger r = curve.getR();

	private final EcPseudoRandomFunction derivation;

	public BasicDerivation(final EcPseudoRandomFunction derivation) {
		this.derivation = derivation;
	}

	/**
	 * Implements basic derivation
	 * 
	 * @throws Exception 
	 */
	@Override
	public EcPoint derive(final EcPoint input) throws Exception {

		// Perform derivation on the input
		return this.derivation.derive(input);

	}

	@Override
	public EcPoint getPublicKey() {
		return this.derivation.getPublicKey();
	}

}
