/*
 * Copyright (c) IBM Corporation 2018. All Rights Reserved.
 * Project name: pross
 * This project is licensed under the MIT License, see LICENSE.
 */

package com.ibm.pross.common.util.crypto.ecc;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;

import com.ibm.pross.common.util.crypto.kdf.HmacKeyDerivationFunction;

/**
 * Implements methods for hashing to an arbitrary point on an elliptic curve
 * 
 * This class uses methods for computing square roots requires: (p % 4) == 3.
 * 
 * @author jresch
 */
public abstract class PointHasher {

	// Useful
	public static final BigInteger TWO = BigInteger.valueOf(2);
	public static final BigInteger THREE = BigInteger.valueOf(3);
	public static final BigInteger FOUR = BigInteger.valueOf(4);

	protected final EcCurve curve;

	protected final BigInteger invTwo;
	protected final BigInteger invFour;

	protected final BigInteger quadResideTestExponent;
	protected final BigInteger squareRootExponent;

	public PointHasher(EcCurve curve) {
		if (!curve.getP().mod(FOUR).equals(THREE)) {
			throw new IllegalArgumentException("p has invalid properties for this class to work");
		}

		this.curve = curve;

		// Calculate and cache quad residue test exponent
		this.invTwo = TWO.modInverse(this.curve.getP());
		this.quadResideTestExponent = this.curve.getP().subtract(BigInteger.ONE).multiply(invTwo)
				.mod(this.curve.getP());

		// Calculate and cache exponent for computing square roots
		this.invFour = FOUR.modInverse(this.curve.getP());
		this.squareRootExponent = this.curve.getP().add(BigInteger.ONE).multiply(invFour).mod(this.curve.getP());
	}

	/**
	 * Determines if a is a quadratic residue modulo prime p, that is, is a =
	 * x^2 mod p, for some x.
	 * 
	 * This uses using Euler's criterion which states that a^((p-1)/2 = 1 mod p,
	 * if a is a quadratic residue See also:
	 * https://en.wikipedia.org/wiki/Euler%27s_criterion
	 *
	 * @param a
	 */
	protected boolean isQuadraticResidue(BigInteger a) {
		BigInteger result = a.modPow(this.quadResideTestExponent, this.curve.getP());
		return result.equals(BigInteger.ONE);
	}

	/**
	 * Computes the square root of a modulo p
	 * 
	 * It requires however that p = 3 (modulo 4)
	 *
	 * @param a
	 */
	protected BigInteger squareRoot(BigInteger a) {
		return a.modPow(this.squareRootExponent, this.curve.getP());
	}

	/**
	 * Hashes to a point on the curve given a string
	 * 
	 * @param input
	 *            Input used to deterministically map to a random point on the
	 *            curve
	 * @return A point on the elliptic curve
	 */
	public EcPoint hashToCurve(final String input) {
		return this.hashToCurve(input.getBytes(StandardCharsets.UTF_8), null);
	}

	/**
	 * Hashes to a point on the curve given a binary input
	 * 
	 * @param input
	 *            Input used to deterministically map to a random point on the
	 *            curve
	 * @param clientSecret
	 *            An optional client-provided secret. If used, the same client
	 *            secret must be supplied in the future.
	 * @return A point on the elliptic curve
	 */
	public EcPoint hashToCurve(final String input, final byte[] clientSecret) {
		return this.hashToCurve(input.getBytes(StandardCharsets.UTF_8), clientSecret);
	}

	/**
	 * Hashes to a point on the curve given a binary input
	 * 
	 * @param input
	 *            Input used to deterministically map to a random point on the
	 *            curve
	 * @return A point on the elliptic curve
	 */
	public EcPoint hashToCurve(final byte[] input) {
		return this.hashToCurve(input, null);
	}

	/**
	 * Hashes to a point on the curve given a binary input
	 * 
	 * @param input
	 *            Input used to deterministically map to a random point on the
	 *            curve
	 * @param clientSecret
	 *            An optional client-provided secret. If used, the same client
	 *            secret must be supplied in the future.
	 * @return A point on the elliptic curve
	 */
	public EcPoint hashToCurve(final byte[] input, final byte[] clientSecret) {

		final HmacKeyDerivationFunction hkdf;
		if (clientSecret == null) {
			// Create an HKDF instance based on the input
			hkdf = new HmacKeyDerivationFunction(HmacKeyDerivationFunction.HDFK_SHA512, input);
		} else {
			// Create an HKDF instance based on the input and a client secret
			hkdf = new HmacKeyDerivationFunction(HmacKeyDerivationFunction.HDFK_SHA512, input, clientSecret);
		}

		final BigInteger p = this.curve.getP();

		final int curveSize = p.bitLength();
		final int bytesToGenerate = ((curveSize + 7) / 8); // Round up as
															// necessary
		final int extraBits = (bytesToGenerate * 8) - curveSize;

		BigInteger iterationCounter = BigInteger.ONE;

		// Use HKDF to derive a a random T value
		
		while (true) {
			final byte[] tBytes = hkdf.createKey(iterationCounter.toByteArray(), bytesToGenerate);
			final BigInteger t = (new BigInteger(1, tBytes)).shiftRight(extraBits);
			
			if (t.compareTo(p) < 0)
			{
				return createPointFromInteger(t);
			}
			
			// Note: it is exceedingly rare that we ever get to this point
			iterationCounter = iterationCounter.add(BigInteger.ONE);
		}	
	}

	/**
	 * Must implement a constant-time algorithm for converting an integer in the
	 * range 0..p to a point on the curve
	 * 
	 * @param t
	 * @return
	 */
	public abstract EcPoint createPointFromInteger(BigInteger t);
}
