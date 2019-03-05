/*
 * Copyright (c) IBM Corporation 2018. All Rights Reserved.
 * Project name: pross
 * This project is licensed under the MIT License, see LICENSE.
 */

package com.ibm.pross.common;

import com.ibm.pross.common.util.crypto.ecc.EcPoint;

/**
 * Implementers of this interface perform ECDH derivation, by performing a
 * scalar multiplication of an input point by a private factor.
 */
public interface EcPseudoRandomFunction {

	/**
	 * Performs ECDH key derivation using a constant private key
	 * 
	 * @param input
	 *            Input must be a point on the curve and must not be the point
	 *            at infinity
	 * @return The result of multiplying the input point by a secret, but
	 *         constant scaling factor
	 */
	public EcPoint derive(final EcPoint input) throws Exception;

	/**
	 * Returns the public key corresponding to the private key used to perform
	 * derivation
	 * 
	 * @return
	 */
	public EcPoint getPublicKey();

}
