/*
 * Copyright (c) IBM Corporation 2018. All Rights Reserved.
 * Project name: pross
 * This project is licensed under the MIT License, see LICENSE.
 */

package com.ibm.pross.common.util.shamir;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;

import com.ibm.pross.common.CommonConfiguration;
import com.ibm.pross.common.DerivationResult;
import com.ibm.pross.common.util.crypto.ecc.EcCurve;
import com.ibm.pross.common.util.crypto.ecc.EcPoint;

public class Polynomials {

	// Static fields
	final public static EcCurve curve = CommonConfiguration.CURVE;
	final public static BigInteger r = curve.getR();
	final public static EcPoint G = curve.getG();

	/**
	 * Evaluates a polynomial defined by the coefficients list (assumed to be in
	 * order from x^0 to x^n-1) at the given coordinate x. All computations are
	 * performed mod m.
	 * 
	 * @param coefficients
	 * @param x
	 * @param modulus
	 * @return A point representing the evaluation of the polynomial F at F(x).
	 */
	public static ShamirShare evaluatePolynomial(final BigInteger[] coefficients, final BigInteger x,
			final BigInteger m) {
		BigInteger y = BigInteger.ZERO;
		BigInteger exponent = BigInteger.ZERO;
		for (int i = 0; i < coefficients.length; i++) {
			BigInteger xTerm = x.modPow(exponent, m);
			y = y.add(coefficients[i].multiply(xTerm));
			exponent = exponent.add(BigInteger.ONE);
		}
		return new ShamirShare(x, y.mod(m));
	}

	/**
	 * Uses Lagrange polynomial interpolation of the provided x-coordinates to
	 * determine a multiplier to use when solving for another x-coordinate at
	 * position "i" using an x-coordinate position at "j". This can be used as a
	 * step in partial rebuilding.
	 * 
	 * @param points
	 *            The x-coordinates of the values being used in this
	 *            interpolation
	 * @param delta
	 *            An optional additional multiplier to prevent use of fractions,
	 *            e.g. n! when n is the maximum possible x-coordinate, otherwise
	 *            may be 1.
	 * @param i
	 *            The x-coordinate which we are considering solving for
	 * @param j
	 *            The given x-coordinate we have and are considering using to
	 *            solve for
	 * @param m
	 * @return Lambda_ij which when multiplied by the y-coordinate at j, will be
	 *         a "partial" slice, which can be summed with others to yield F(i)
	 * @throws BadArgumentException
	 * @throws Exception
	 *             When the numerator is not evenly divisible by the denominator
	 */
	public static BigInteger interpolatePartial(final BigInteger[] xCoords, final BigInteger i, final BigInteger j,
			final BigInteger modulo) {
		BigInteger numerator = BigInteger.ONE;
		BigInteger denominator = BigInteger.ONE;

		for (int k = 0; k < xCoords.length; k++) {
			BigInteger jPrime = xCoords[k];
			if (!jPrime.equals(j)) {
				numerator = numerator.multiply(i.subtract(jPrime)).mod(modulo);
				denominator = denominator.multiply(j.subtract(jPrime)).mod(modulo);
			}
		}

		final BigInteger invDenominator = denominator.modInverse(modulo);
		return numerator.multiply(invDenominator).mod(modulo);
	}

	public static BigInteger interpolateComplete(final Collection<ShamirShare> shares, int threshold, int x) {
		if (shares.size() < threshold) {
			throw new IllegalArgumentException("Fewer than a threshold number of results provided!");
		}

		// Determine coordinates
		final BigInteger[] xCoords = new BigInteger[threshold];
		final List<ShamirShare> shareList = new ArrayList<>(shares);
		for (int i = 0; i < threshold; i++) {
			xCoords[i] = shareList.get(i).getX();
		}

		// Position to solve for
		final BigInteger xPosition = BigInteger.valueOf(x);

		// Interpolate polynomial
		BigInteger sum = BigInteger.ZERO;
		for (int i = 0; i < threshold; i++) {
			final ShamirShare share = shareList.get(i);

			final BigInteger j = share.getX();
			final BigInteger L_ij = Polynomials.interpolatePartial(xCoords, xPosition, j, r);

			final BigInteger product = share.getY().multiply(L_ij).mod(r);

			sum = sum.add(product).mod(r);
		}

		return sum;
	}

	/**
	 * Combines a threshold number of derivation results computed from
	 * individual shares to recover the derived result based on the secret
	 * represent by those shares
	 * 
	 * @param responses
	 *            A response computed using one of the shares
	 * @param threshold
	 *            The recovery threshold for the secret sharing
	 * @return The EcPoint which is equal to the point derived from multiplying
	 *         the input point with the secret
	 * @throws IllegalArgumentException
	 */
	public static EcPoint interpolateExponents(final List<DerivationResult> responses, final int threshold, final int xPosition)
			throws IllegalArgumentException {

		if (responses.size() < threshold) {
			throw new IllegalArgumentException("Fewer than a threshold number of results provided!");
		}

		final BigInteger r = CommonConfiguration.CURVE.getR();

		// Determine coordinates
		final BigInteger[] xCoords = new BigInteger[threshold];
		for (int i = 0; i < threshold; i++) {
			final DerivationResult toprfResponse = responses.get(i);
			xCoords[i] = toprfResponse.getIndex();
		}

		// Interpolate polynomial
		EcPoint sum = null;
		for (int i = 0; i < threshold; i++) {
			final DerivationResult toprfResponse = responses.get(i);

			final BigInteger j = toprfResponse.getIndex();
			final EcPoint outputShare = toprfResponse.getDerivedSharePoint();
			final BigInteger L_ij = Polynomials.interpolatePartial(xCoords, BigInteger.valueOf(xPosition), j, r);

			final EcPoint product = CommonConfiguration.CURVE.multiply(outputShare, L_ij);

			if (sum == null)
				sum = product;
			else
				sum = CommonConfiguration.CURVE.addPoints(sum, product);
		}

		return sum;
	}
}
