/*
 * Copyright (c) IBM Corporation 2018. All Rights Reserved.
 * Project name: pross
 * This project is licensed under the MIT License, see LICENSE.
 */

package com.ibm.pross.client;

import com.ibm.pross.common.CommonConfiguration;
import com.ibm.pross.common.EcPseudoRandomFunction;
import com.ibm.pross.common.util.crypto.ecc.EcCurve;
import com.ibm.pross.common.util.crypto.ecc.EcPoint;
import com.ibm.pross.common.util.crypto.kdf.HmacKeyDerivationFunction;
import com.ibm.pross.common.util.crypto.kdf.EntropyExtractor;

public class PrfClient {

	// Static fields
	final public static EcCurve curve = CommonConfiguration.CURVE;
	
	private final EcPseudoRandomFunction derivation;
	
	public PrfClient(final EcPseudoRandomFunction derivation)
	{
		this.derivation = derivation;
	}
	
	public HmacKeyDerivationFunction deriveKeyGeneratorFromBytes(byte[] input) throws Exception
	{
		// Derive point from input bytes
		final EcPoint derivedPoint = this.derivePointFromBytes(input);
		
		// Create key generator from input and derived point
		return EntropyExtractor.getKeyGenerator(input, derivedPoint);
	}
	
	public EcPoint derivePointFromBytes(byte[] input) throws Exception {
		
		// Hash input to point on the curve
		final EcPoint inputPoint = curve.getPointHasher().hashToCurve(input);
		
		// Return derived point
		return this.derivation.derive(inputPoint);
	}
	
}
