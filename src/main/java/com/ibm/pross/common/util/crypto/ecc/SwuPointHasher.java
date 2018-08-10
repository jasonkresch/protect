/*
 * Copyright (c) IBM Corporation 2018. All Rights Reserved.
 * Project name: pross
 * This project is licensed under the MIT License, see LICENSE.
 */

package com.ibm.pross.common.util.crypto.ecc;

import java.math.BigInteger;

/**
 * Implements methods for hashing to an arbitrary point on an elliptic curve
 * 
 * This class uses methods for computing square roots requires: (p % 4) == 3.
 * 
 * This uses the "Simplified SWU" method in section 4.3 of:
 * https://datatracker.ietf.org/doc/draft-sullivan-cfrg-hash-to-curve/?include_text=1
 * 
 * See also: "Efficient Indifferentiable Hashing into Ordinary Elliptic Curves"
 * https://eprint.iacr.org/2009/340.pdf
 * 
 * @author jresch
 */
public class SwuPointHasher extends PointHasher {

	private final BigInteger negativeBoverA;

	public SwuPointHasher(final EcCurve curve) {
		super(curve);

		// Calculate a value used to hashing to the curve in constant time
		final BigInteger negativeB = this.curve.getP().subtract(this.curve.getB());
		final BigInteger inverseA = this.curve.getA().modInverse(this.curve.getP());

		this.negativeBoverA = negativeB.multiply(inverseA).mod(this.curve.getP());
	}

	@Override
	public EcPoint createPointFromInteger(final BigInteger t) {

		final BigInteger p = this.curve.getP();

		final BigInteger tSquared = t.modPow(TWO, p);
		final BigInteger negativeTSquared = p.subtract(tSquared);
		final BigInteger tToFourth = negativeTSquared.modPow(TWO, p);
		final BigInteger tPowerSum = tToFourth.add(negativeTSquared);

		final BigInteger inverseTPowerSum = tPowerSum.modInverse(p);

		final BigInteger X2 = this.negativeBoverA.multiply(inverseTPowerSum.add(BigInteger.ONE)).mod(p);
		final BigInteger X3 = negativeTSquared.multiply(X2).mod(p);

		final BigInteger h2 = this.curve.computeYSquared(X2);
		final BigInteger h3 = this.curve.computeYSquared(X3);

		final BigInteger y2 = this.squareRoot(h2);
		final BigInteger y3 = this.squareRoot(h3);

		// Evaluate right hand side of the equation
		int h2Valid = y2.multiply(y2).mod(p).equals(h2) ? 1 : 0;
		int h3Valid = y3.multiply(y3).mod(p).equals(h3) ? 1 : 0;

		if ((h2Valid + h3Valid) == 1) // Ensure exactly one is valid
		{
			// We use a switch to ensure constant time
			switch (h2Valid) {
			case 1:
				return new EcPoint(X2, y2);
			case 0:
				return new EcPoint(X3, y3);
			default:
				throw new RuntimeException("Something went wrong!");

			}
		} else {
			throw new RuntimeException("Something went wrong!");
		}
	}
}
