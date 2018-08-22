/*
 * Copyright (c) IBM Corporation 2018. All Rights Reserved.
 * Project name: pross
 * This project is licensed under the MIT License, see LICENSE.
 */

package com.ibm.pross.client.prf;

import java.math.BigInteger;

import com.ibm.pross.common.CommonConfiguration;
import com.ibm.pross.common.PseudoRandomFunction;
import com.ibm.pross.common.util.crypto.ecc.EcCurve;
import com.ibm.pross.common.util.crypto.ecc.EcPoint;

public class BasicDerivation implements PseudoRandomFunction {

	// Static fields
	final public static EcCurve curve = CommonConfiguration.CURVE;
	final public static BigInteger r = curve.getR();

	private final PseudoRandomFunction derivation;

	public BasicDerivation(final PseudoRandomFunction derivation) {
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
