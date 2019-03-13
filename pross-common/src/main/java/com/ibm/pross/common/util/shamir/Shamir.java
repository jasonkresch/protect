/*
 * Copyright (c) IBM Corporation 2018. All Rights Reserved.
 * Project name: pross
 * This project is licensed under the MIT License, see LICENSE.
 */

package com.ibm.pross.common.util.shamir;

import java.math.BigInteger;

import com.ibm.pross.common.config.CommonConfiguration;
import com.ibm.pross.common.util.RandomNumberGenerator;
import com.ibm.pross.common.util.crypto.ecc.EcCurve;
import com.ibm.pross.common.util.crypto.ecc.EcPoint;

public class Shamir {

	// Static fields
	final public static EcCurve curve = CommonConfiguration.CURVE;
	final public static BigInteger r = curve.getR();
	final public static EcPoint G = curve.getG();

	/**
	 * Generates completely random set of a threshold number of coefficients
	 * along with a random secret represented by coefficients[0]
	 * 
	 * @param threshold
	 * @return
	 */
	public static BigInteger[] generateCoefficients(final int threshold) {
		// Create secret shares of the "OPRF key", secret is coefficients[0]
		return RandomNumberGenerator.generateRandomArray(threshold, r);
	}

	/**
	 * Generates a set of co-efficients, such that the y-intercept of the given
	 * indexOfZero x-coordinate is zero. This is used to implement secure
	 * reconstruction of lost shares.
	 * 
	 * @param threshold
	 * @param indexOfZero
	 * @return
	 */
	public static BigInteger[] generateCoefficients(final int threshold, final int indexOfZero) {
		final BigInteger[] coefficients = generateCoefficients(threshold);

		final BigInteger rebuildingShareholderIndex = BigInteger.valueOf(indexOfZero);

		BigInteger sum = BigInteger.ZERO;
		for (int i = 1; i < threshold; i++) {
			sum = sum.add(coefficients[i].multiply(rebuildingShareholderIndex.pow(i))).mod(r);
		}

		// Make it "negative"
		coefficients[0] = r.subtract(sum);
		return coefficients;

	}

	/**
	 * Generate's Feldman Verifiable Secret Sharing values, which represent a
	 * generator raised to the power of the coefficients of the secret sharing
	 * polynomial used to generate shares
	 * 
	 * @param coefficients
	 * @return
	 */
	public static EcPoint[] generateFeldmanValues(final BigInteger[] coefficients) {

		final EcPoint[] feldmanValues = new EcPoint[coefficients.length];
		for (int i = 0; i < coefficients.length; i++) {
			feldmanValues[i] = curve.multiply(G, coefficients[i]);
		}
		return feldmanValues;
	}
	
	/**
	 * Generate's Feldman Verifiable Secret Sharing values, which represent a
	 * generator raised to the power of the coefficients of the secret sharing
	 * polynomial used to generate shares, taking a base of the exponent as an input:
	 * 
	 * @param coefficients
	 * @param base
	 * @return
	 */
	public static EcPoint[] generateFeldmanValues(final BigInteger[] coefficients, final EcPoint base) {

		final EcPoint[] feldmanValues = new EcPoint[coefficients.length];
		for (int i = 0; i < coefficients.length; i++) {
			feldmanValues[i] = curve.multiply(base, coefficients[i]);
		}
		return feldmanValues;
	}

	/**
	 * Generates Shamir Secret shares from the polynomial defined by the
	 * provided coefficients
	 * 
	 * @param coefficients
	 *            Set of integer coefficients where coefficients[0] is the free
	 *            coefficient and coefficients[t-1] is for the x^(t-1) term
	 * @param n
	 *            Number of shares to generate. The returned shares are f(1),
	 *            f(2), ..., f(n)
	 * @return
	 */
	public static ShamirShare[] generateShares(final BigInteger[] coefficients, final int n) {

		// Evaluate the polynomial from 1 to n (must not evaluate at zero!)
		ShamirShare[] shares = new ShamirShare[n];
		for (int i = 0; i < n; i++) {
			final BigInteger xCoord = BigInteger.valueOf(i + 1);
			shares[i] = Polynomials.evaluatePolynomial(coefficients, xCoord, r);
		}

		return shares;
	}

	/**
	 * Performs verifiable secret sharing using Feldman values
	 * 
	 * @param share
	 *            The shamir share to be verified
	 * @param feldmanValues
	 *            The powers of the polynomial's coefficients over a field
	 * @throws IllegalArgumentException
	 *             If share is not consistent with the Feldman values
	 */
	public static void verifyShamirShareConsistency(final ShamirShare share, final EcPoint[] feldmanValues)
			throws IllegalArgumentException {

		final EcPoint expected = curve.multiply(G, share.getY());

		final EcPoint sum = computeSharePublicKey(feldmanValues, share.getX().intValue());

		if (!expected.equals(sum)) {
			throw new IllegalArgumentException("Invalid share received!");
		}
	}

	/**
	 * Computes the set of share public keys, which is a generator raised to the
	 * power of the share. These can be used to verify computations performed
	 * using the share, such as in a T-OPRF. They are also used to verify the
	 * consistency of reconstructed shares.
	 * 
	 * @param feldmanValues
	 *            The feldman values for the secret sharing
	 * @param n
	 *            The number of shareholders
	 * @return
	 */
	public static EcPoint[] computeSharePublicKeys(final EcPoint[] feldmanValues, final int n) {

		final EcPoint[] sharePublicKeys = new EcPoint[n];
		for (int i = 0; i < n; i++) {
			sharePublicKeys[i] = computeSharePublicKey(feldmanValues, i+1);
		}

		return sharePublicKeys;
	}

	/**
	 * Generates a single shareholder's share public key
	 * 
	 * @param feldmanValues
	 * @param shareholderIndex
	 * @return
	 */
	public static EcPoint computeSharePublicKey(final EcPoint[] feldmanValues, final int xPosition) {
		final BigInteger index = BigInteger.valueOf(xPosition);

		EcPoint sum = feldmanValues[0];
		for (int i = 1; i < feldmanValues.length; i++) {
			final EcPoint product = curve.multiply(feldmanValues[i], index.pow(i));
			sum = curve.addPoints(sum, product);
		}

		return sum;
	}

}
