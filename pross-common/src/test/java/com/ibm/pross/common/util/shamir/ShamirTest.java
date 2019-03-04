/*
 * Copyright (c) IBM Corporation 2018. All Rights Reserved.
 * Project name: pross
 * This project is licensed under the MIT License, see LICENSE.
 */

package com.ibm.pross.common.util.shamir;

import static org.junit.Assert.fail;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.junit.Assert;
import org.junit.Test;

import com.ibm.pross.common.CommonConfiguration;
import com.ibm.pross.common.DerivationResult;
import com.ibm.pross.common.util.RandomNumberGenerator;
import com.ibm.pross.common.util.crypto.ecc.EcCurve;
import com.ibm.pross.common.util.crypto.ecc.EcPoint;

public class ShamirTest {

	// Static fields
	final public static EcCurve curve = CommonConfiguration.CURVE;
	final public static BigInteger r = curve.getR();
	final public static EcPoint G = curve.getG();

	@Test
	public void testGenerateCoefficientsInt() {
		fail("Not yet implemented");
	}

	@Test
	public void testGenerateCoefficientsIntInt() {

		int n = 9;
		int threshold = 5;
		int repairIndex = 2;

		// Create coefficients
		final BigInteger[] coefficients = Shamir.generateCoefficients(threshold, repairIndex);

		// Create shares
		final Set<ShamirShare> shares = new HashSet<>();
		for (int i = 1; i <= n; i++) {
			final BigInteger x = BigInteger.valueOf(i);
			final ShamirShare share = Polynomials.evaluatePolynomial(coefficients, x, r);
			shares.add(share);
		}

		// Interpolate at different points, ensure non-zero at all positions
		// except repair index
		for (int i = 0; i <= n; i++) {
			if (i == repairIndex) {
				final BigInteger result = Polynomials.interpolateComplete(shares, threshold, i);
				Assert.assertEquals(BigInteger.ZERO, result);
			} else {
				final BigInteger result = Polynomials.interpolateComplete(shares, threshold, i);
				Assert.assertNotEquals(BigInteger.ZERO, result);
			}
		}

		// Generate feldman values
		final EcPoint[] feldmanValues = Shamir.generateFeldmanValues(coefficients);

		// Verify feldman co-efficients are consistent with f(repair_index) == 0
		final ShamirShare zeroIntercept = new ShamirShare(BigInteger.valueOf(repairIndex), BigInteger.ZERO);
		Shamir.verifyShamirShareConsistency(zeroIntercept, feldmanValues);
	}

	@Test
	public void testGenerateCoefficientsMaskReconstruction() {

		int n = 9;
		int threshold = 5;
		int repairIndex = 2;

		// Create original secret share co-efficients and shares
		final BigInteger[] originalCoefficients = Shamir.generateCoefficients(threshold);
		final List<ShamirShare> originalShares = Arrays.asList(Shamir.generateShares(originalCoefficients, n));

		// Create masking coefficients and shares
		final BigInteger[] maskingCoefficients = Shamir.generateCoefficients(threshold, repairIndex);
		final List<ShamirShare> maskingShares = Arrays.asList(Shamir.generateShares(maskingCoefficients, n));

		// Create sum shares
		final Set<ShamirShare> sumShares = new HashSet<>();
		for (int i = 0; i < originalShares.size(); i++) {
			final ShamirShare originalShare = originalShares.get(i);
			final ShamirShare maskingShare = maskingShares.get(i);
			final ShamirShare sumShare = new ShamirShare(originalShare.getX(),
					originalShare.getY().add(maskingShare.getY().mod(r)));
			sumShares.add(sumShare);
		}

		// Interpolate at different points, ensure non-zero at all positions
		// except repair index when using just masking shares
		for (int i = 0; i <= n; i++) {
			if (i == repairIndex) {
				final BigInteger result = Polynomials.interpolateComplete(maskingShares, threshold, i);
				Assert.assertEquals(BigInteger.ZERO, result);
			} else {
				final BigInteger result = Polynomials.interpolateComplete(maskingShares, threshold, i);
				Assert.assertNotEquals(BigInteger.ZERO, result);
			}
		}

		// Interpolate at different points, ensure wrong values at all positions
		// except repair index when using sum shares
		for (int i = 0; i <= n; i++) {
			final BigInteger originalResult = Polynomials.interpolateComplete(originalShares, threshold, i);
			if (i == repairIndex) {
				final BigInteger maskedResult = Polynomials.interpolateComplete(sumShares, threshold, i);
				Assert.assertEquals(originalResult, maskedResult);
			} else {
				final BigInteger maskedResult = Polynomials.interpolateComplete(sumShares, threshold, i);
				Assert.assertNotEquals(originalResult, maskedResult);
			}
		}
	}

	@Test
	public void testGenerateCoefficientsMultipleMaskingsReconstruction() {

		int n = 9;
		int threshold = 5;
		int repairIndex = 2;

		// Create original secret share co-efficients and shares
		final BigInteger[] originalCoefficients = Shamir.generateCoefficients(threshold);
		final List<ShamirShare> originalShares = Arrays.asList(Shamir.generateShares(originalCoefficients, n));

		// Create first masking coefficients and shares
		final BigInteger[] maskingCoefficients1 = Shamir.generateCoefficients(threshold, repairIndex);
		final List<ShamirShare> maskingShares1 = Arrays.asList(Shamir.generateShares(maskingCoefficients1, n));

		// Create second masking coefficients and shares
		final BigInteger[] maskingCoefficients2 = Shamir.generateCoefficients(threshold, repairIndex);
		final List<ShamirShare> maskingShares2 = Arrays.asList(Shamir.generateShares(maskingCoefficients2, n));

		// Create sum shares
		final Set<ShamirShare> sumShares = new HashSet<>();
		for (int i = 0; i < originalShares.size(); i++) {
			final ShamirShare originalShare = originalShares.get(i);
			final ShamirShare maskingShare1 = maskingShares1.get(i);
			final ShamirShare maskingShare2 = maskingShares2.get(i);
			final ShamirShare sumShare = new ShamirShare(originalShare.getX(),
					originalShare.getY().add(maskingShare1.getY()).add(maskingShare2.getY()).mod(r));
			sumShares.add(sumShare);
		}

		// Interpolate at different points, ensure non-zero at all positions
		// except repair index when using just masking shares
		for (int i = 0; i <= n; i++) {
			if (i == repairIndex) {
				final BigInteger result1 = Polynomials.interpolateComplete(maskingShares1, threshold, i);
				Assert.assertEquals(BigInteger.ZERO, result1);

				final BigInteger result2 = Polynomials.interpolateComplete(maskingShares2, threshold, i);
				Assert.assertEquals(BigInteger.ZERO, result2);
			} else {
				final BigInteger result = Polynomials.interpolateComplete(maskingShares1, threshold, i);
				Assert.assertNotEquals(BigInteger.ZERO, result);

				final BigInteger result2 = Polynomials.interpolateComplete(maskingShares2, threshold, i);
				Assert.assertNotEquals(BigInteger.ZERO, result2);
			}
		}

		// Interpolate at different points, ensure wrong values at all positions
		// except repair index when using sum shares
		for (int i = 0; i <= n; i++) {
			final BigInteger originalResult = Polynomials.interpolateComplete(originalShares, threshold, i);

			if (i == repairIndex) {
				final BigInteger maskedResult = Polynomials.interpolateComplete(sumShares, threshold, i);
				Assert.assertEquals(originalResult, maskedResult);
			} else {
				final BigInteger maskedResult = Polynomials.interpolateComplete(sumShares, threshold, i);
				Assert.assertNotEquals(originalResult, maskedResult);
			}
		}
	}

	@Test
	public void testGenerateShares() {

		int n = 9;
		int threshold = 5;

		// Create coefficients
		final BigInteger[] coefficients = Shamir.generateCoefficients(threshold);

		final BigInteger secret = RandomNumberGenerator.generateRandomInteger(r);
		coefficients[0] = secret;

		// Create shares
		final ShamirShare[] shares = Shamir.generateShares(coefficients, n);
		final Set<ShamirShare> shareSet = new HashSet<>(Arrays.asList(shares));

		// Interpolate at different points, secret matches for position 0 only
		for (int i = 0; i <= n; i++) {
			if (i == 0) {
				final BigInteger result = Polynomials.interpolateComplete(shareSet, threshold, i);
				Assert.assertEquals(secret, result);
			} else {
				final BigInteger result = Polynomials.interpolateComplete(shareSet, threshold, i);
				Assert.assertNotEquals(secret, result);
			}
		}
	}

	@Test
	public void testProactiveRefresh() {

		final int n = 9;
		final int threshold = 5;

		// Create coefficients
		final BigInteger[] coefficients = Shamir.generateCoefficients(threshold);

		final BigInteger secret = RandomNumberGenerator.generateRandomInteger(r);
		coefficients[0] = secret;

		// Create shares
		final ShamirShare[] shares = Shamir.generateShares(coefficients, n);
		System.out.println("Original Shares: " + Arrays.toString(shares));
		final Set<ShamirShare> shareSet = new HashSet<>(Arrays.asList(shares));

		// Use shares as inputs to new T new sharings
		int count = 0;
		final Map<BigInteger, ShamirShare[]> subSharings = new HashMap<>();
		final BigInteger[] xCoords = new BigInteger[threshold];
		for (final ShamirShare share : shareSet) {
			xCoords[count++] = share.getX();
			final BigInteger[] subCoefficients = Shamir.generateCoefficients(threshold);
			subCoefficients[0] = share.getY();
			final ShamirShare[] subShares = Shamir.generateShares(subCoefficients, n);
			subSharings.put(share.getX(), subShares);
			if (count == threshold) {
				break;
			}
		}

		// Solve for the updated shares using the sharings
		final ShamirShare[] newShares = new ShamirShare[n];
		for (int i = 1; i <= n; i++) {
			// Compute sum to form new share for shareholder i
			final BigInteger x = BigInteger.valueOf(i);
			BigInteger y = BigInteger.ZERO;

			for (final BigInteger j : xCoords) {
				// j is the index of the shareholder who provided us with our share
				final ShamirShare[] subShares = subSharings.get(j);

				// jY is j's share for us
				final BigInteger jY = subShares[i - 1].getY();

				// Lagrange co-efficient
				final BigInteger l = Polynomials.interpolatePartial(xCoords, BigInteger.ZERO, j, r);

				// Compute sum
				y = y.add(jY.multiply(l).mod(r));
			}

			newShares[i - 1] = new ShamirShare(x, y.mod(r));
		}

		System.out.println("New Shares:      " + Arrays.toString(newShares));

		// Attempt to decode using the old shares
		final BigInteger secret1 = Polynomials.interpolateComplete(shareSet, threshold, 0);
		Assert.assertEquals(secret, secret1);

		// Attempt to decode using the new shares
		final Set<ShamirShare> newShareSet = new HashSet<>(Arrays.asList(newShares));
		final BigInteger secret2 = Polynomials.interpolateComplete(newShareSet, threshold, 0);
		Assert.assertEquals(secret, secret2);

		// Verify all the new shares are different
		for (int i = 0; i < n; i++) {
			Assert.assertNotEquals(shares[i], newShares[i]);
		}
	}

	@Test
	public void testShareRecovery() {

		final int n = 9;
		final int threshold = 5;

		// Create coefficients
		final BigInteger[] coefficients = Shamir.generateCoefficients(threshold);

		final BigInteger secret = RandomNumberGenerator.generateRandomInteger(r);
		coefficients[0] = secret;

		// Create shares
		final ShamirShare[] shares = Shamir.generateShares(coefficients, n);
		System.out.println("Original Shares: " + Arrays.toString(shares));
		final Set<ShamirShare> shareSet = new HashSet<>(Arrays.asList(shares));

		// Use shares as inputs to new T new sharings
		int count = 0;
		final Map<BigInteger, ShamirShare[]> subSharings = new HashMap<>();
		final BigInteger[] xCoords = new BigInteger[threshold];
		for (final ShamirShare share : shareSet) {
			xCoords[count++] = share.getX();
			final BigInteger[] subCoefficients = Shamir.generateCoefficients(threshold);
			subCoefficients[0] = share.getY();
			final ShamirShare[] subShares = Shamir.generateShares(subCoefficients, n);
			subSharings.put(share.getX(), subShares);
			if (count == threshold) {
				break;
			}
		}

		// Each party (i) computes its contributions for all the others (k)
		final ShamirShare allRecoverySharings[][] = new ShamirShare[n][n];
		for (int i = 1; i <= n; i++) {

			// Shareholder_i will create a contribution for shareholder k
			for (int k = 1; k <= n; k++) {
				final BigInteger K = BigInteger.valueOf(k);

				// Use each of the j subsharings
				BigInteger y = BigInteger.ZERO;
				for (final BigInteger j : xCoords) {
					// j is the index of the shareholder who provided us with our share
					final ShamirShare[] subShares = subSharings.get(j);

					// jY is j's share for us
					final BigInteger jY = subShares[i - 1].getY();

					// Lagrange co-efficient
					final BigInteger l = Polynomials.interpolatePartial(xCoords, K, j, r);

					// Compute sum
					y = y.add(jY.multiply(l).mod(r));
				}

				allRecoverySharings[i - 1][k - 1] = new ShamirShare(K, y.mod(r));
			}
		}

		final ShamirShare[] newShares = new ShamirShare[n];
		for (int k = 1; k <= n; k++) {
			// Compute sum to form new share for shareholder i
			final BigInteger K = BigInteger.valueOf(k);
			BigInteger y = BigInteger.ZERO;

			for (final BigInteger j : xCoords) {
				// j is the index of the shareholder who provided us with a contribution
				final BigInteger contrib = allRecoverySharings[j.intValue()-1][k-1].getY();

				// Lagrange co-efficient
				final BigInteger l = Polynomials.interpolatePartial(xCoords, BigInteger.ZERO, j, r);

				// Compute sum
				y = y.add(contrib.multiply(l).mod(r));
			}

			newShares[k - 1] = new ShamirShare(K, y.mod(r));
		}

		System.out.println("New Shares:      " + Arrays.toString(newShares));

		// Attempt to decode using the old shares
		final BigInteger secret1 = Polynomials.interpolateComplete(shareSet, threshold, 0);
		Assert.assertEquals(secret, secret1);

		// Attempt to decode using the new shares
		final Set<ShamirShare> newShareSet = new HashSet<>(Arrays.asList(newShares));
		final BigInteger secret2 = Polynomials.interpolateComplete(newShareSet, threshold, 0);
		Assert.assertEquals(secret, secret2);

		// Verify all the new shares are different
		for (int i = 0; i < n; i++) {
			Assert.assertEquals(shares[i], newShares[i]);
		}
	}

	@Test
	public void testVerifyShamirShareConsistency() {
		fail("Not yet implemented");
	}

	@Test
	public void testComputeSharePublicKeys() {
		fail("Not yet implemented");
	}

	@Test
	public void testVerifyShamirShareConsistencyNoFreeCoefficient() {
		fail("Not yet implemented");
	}

	@Test
	public void testComputeUpdatedPublicKeys() {
		fail("Not yet implemented");
	}

	@Test
	public void testInterpolateCoefficients() {
		int n = 9;
		int threshold = 5;

		// Create coefficients
		final BigInteger[] coefficients = Shamir.generateCoefficients(threshold);
		System.out.println("Original Coefficients:  " + Arrays.toString(coefficients));

		// Create shares
		final ShamirShare[] shares = Shamir.generateShares(coefficients, n);
		final Set<ShamirShare> shareSet = new HashSet<>(Arrays.asList(shares));

		// Attempt to recover coefficients from points
		final BigInteger[] recoveredCoefficients = Polynomials.interpolateCoefficients(shareSet, threshold);
		System.out.println("Recovered Coefficients: " + Arrays.toString(recoveredCoefficients));

		Assert.assertArrayEquals(coefficients, recoveredCoefficients);
	}

	@Test
	public void testInterpolateCoefficientsExponents() {
		int n = 9;
		int threshold = 5;

		// Create coefficients
		final BigInteger[] coefficients = Shamir.generateCoefficients(threshold);
		final EcPoint[] feldmanCoefficients = Shamir.generateFeldmanValues(coefficients, CommonConfiguration.h);
		System.out.println("Original Feldman Coefficients:  " + Arrays.toString(feldmanCoefficients));

		// Create shares
		final ShamirShare[] shares = Shamir.generateShares(coefficients, n);
		final Set<ShamirShare> shareSet = new HashSet<>(Arrays.asList(shares));

		// Create derivation results
		List<DerivationResult> results = new ArrayList<>();
		for (ShamirShare share : shareSet) {
			final EcPoint derivedSharePoint = curve.multiply(CommonConfiguration.h, share.getY());
			results.add(new DerivationResult(share.getX(), derivedSharePoint));
		}

		// Attempt to recover coefficients from points
		final EcPoint[] recoveredCoefficients = Polynomials.interpolateCoefficientsExponents(results, threshold);
		System.out.println("Recovered Feldman Coefficients: " + Arrays.toString(recoveredCoefficients));

		Assert.assertArrayEquals(feldmanCoefficients, recoveredCoefficients);
	}

}
