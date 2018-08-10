/*
 * Copyright (c) IBM Corporation 2018. All Rights Reserved.
 * Project name: pross
 * This project is licensed under the MIT License, see LICENSE.
 */

package com.ibm.pross.common.util.crypto.ecc;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.Collection;

import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

import com.ibm.pross.common.util.RandomNumberGenerator;

@RunWith(Parameterized.class)
public class EcCurveTest {

	@Parameters(name = "{0}")
	public static Collection<Object[]> data() {
		return Arrays.asList(new Object[][] { { "Java-256", EcCurve.secp256r1 }, { "Java-384", EcCurve.secp384r1 },
				{ "Java-521", EcCurve.secp521r1 }, { "BC-256", EcCurveBc.createByName(EcCurve.secp256r1.getName()) },
				{ "BC-384", EcCurveBc.createByName(EcCurve.secp384r1.getName()) },
				{ "BC-521", EcCurveBc.createByName(EcCurve.secp521r1.getName()) } });
	}

	private final EcCurve curveUnderTest;

	public EcCurveTest(final String impl, final EcCurve curveUnderTest) {
		this.curveUnderTest = curveUnderTest;
	}

	@Test
	public void testGIsPointOnCurve() {
		EcPoint G = this.curveUnderTest.getG();
		Assert.assertTrue(this.curveUnderTest.isPointOnCurve(G));
	}

	@Test
	public void testAddAndMultiplyPoints() {

		// Test basic point doubling logic
		EcPoint G = this.curveUnderTest.getG();
		EcPoint DoubleG = this.curveUnderTest.pointDouble(G);
		EcPoint GTimes2 = this.curveUnderTest.multiply(G, BigInteger.valueOf(2));
		Assert.assertEquals(GTimes2, DoubleG);

		// Test basic addition
		EcPoint TripleG = this.curveUnderTest.addPoints(G, DoubleG);
		EcPoint GTimes3 = this.curveUnderTest.multiply(G, BigInteger.valueOf(3));
		Assert.assertEquals(GTimes3, TripleG);

		// Test more advanced addition
		EcPoint GTimes349 = this.curveUnderTest.multiply(G, BigInteger.valueOf(349));
		EcPoint GTimes782 = this.curveUnderTest.multiply(G, BigInteger.valueOf(782));
		EcPoint GTimes349PlusGTimes782 = this.curveUnderTest.addPoints(GTimes349, GTimes782);
		EcPoint GTimes349Plus782 = this.curveUnderTest.multiply(G, BigInteger.valueOf(349 + 782));
		Assert.assertEquals(GTimes349Plus782, GTimes349PlusGTimes782);
	}

	@Test
	public void testCurveDivision() {

		// Generate random factor
		BigInteger factor = RandomNumberGenerator.generateRandomInteger(this.curveUnderTest.getP());

		// Compute inverse of factor
		BigInteger inverse = factor.modInverse(this.curveUnderTest.getR());

		EcPoint G = this.curveUnderTest.getG();
		EcPoint product = this.curveUnderTest.multiply(G, factor);
		EcPoint recovered = this.curveUnderTest.multiply(product, inverse);
		Assert.assertEquals(G, recovered);

	}

	@Test
	public void testMultiplyPerformanceOnG() {

		// Generate random factor
		BigInteger factor = RandomNumberGenerator.generateRandomInteger(this.curveUnderTest.getR());

		EcPoint G = this.curveUnderTest.getG();

		EcPoint product = this.curveUnderTest.multiply(G, factor);
		for (int i = 0; i < 100; i++) {
			product = this.curveUnderTest.multiply(product, factor);
		}
	}

	@Test
	public void testMultiplyPerformanceOnRandomPoint() {

		// Generate random factor
		BigInteger factor = RandomNumberGenerator.generateRandomInteger(this.curveUnderTest.getR());

		// Create point from G
		EcPoint G = this.curveUnderTest.getG();

		// Perform derivation
		EcPoint product = this.curveUnderTest.multiply(G, factor);

		// Performance loop
		for (int i = 0; i < 100; i++) {
			this.curveUnderTest.multiply(product, factor);
		}
	}

	@Test
	public void testExponentPerformance() {

		// Generate random factor
		BigInteger power = RandomNumberGenerator.generateRandomInteger(this.curveUnderTest.getP());

		BigInteger base = RandomNumberGenerator.generateRandomInteger(this.curveUnderTest.getP());
		for (int i = 0; i < 100; i++) {
			base = base.modPow(power, this.curveUnderTest.getP());
		}
	}

	@Test
	public void testAddPointAtInfinity() {

		final EcPoint pai = EcPoint.pointAtInfinity;

		final EcPoint result0 = this.curveUnderTest.addPoints(pai, pai);
		Assert.assertEquals(pai, result0);

		final EcPoint result1 = this.curveUnderTest.addPoints(this.curveUnderTest.getG(), pai);
		Assert.assertEquals(this.curveUnderTest.getG(), result1);

		final EcPoint result2 = this.curveUnderTest.addPoints(pai, this.curveUnderTest.getG());
		Assert.assertEquals(this.curveUnderTest.getG(), result2);
	}

	@Test
	public void testMultiplyPointAtInfinity() {

		final EcPoint pai = EcPoint.pointAtInfinity;

		final EcPoint result1 = this.curveUnderTest.multiply(pai, BigInteger.valueOf(5));
		Assert.assertEquals(pai, result1);

		final EcPoint result2 = this.curveUnderTest.multiply(pai, BigInteger.valueOf(5));
		Assert.assertEquals(pai, result2);
	}

	@Test
	public void testMultiplyZero() {

		final EcPoint pai = EcPoint.pointAtInfinity;

		final EcPoint result1 = this.curveUnderTest.multiply(this.curveUnderTest.getG(), BigInteger.ZERO);
		Assert.assertEquals(pai, result1);

		final EcPoint result2 = this.curveUnderTest.multiply(this.curveUnderTest.getG(), this.curveUnderTest.getR());
		Assert.assertEquals(pai, result2);
	}

	@Test
	public void testSubtractPoints() {

		final EcPoint pai = EcPoint.pointAtInfinity;

		final EcPoint result1 = this.curveUnderTest.addPoints(this.curveUnderTest.getG(),
				this.curveUnderTest.reflectPoint(this.curveUnderTest.getG()));

		Assert.assertEquals(pai, result1);

	}
	
	@Test
	public void pointAtInfinityIsOnCurve()
	{
		final EcPoint pai = EcPoint.pointAtInfinity;
		Assert.assertTrue(this.curveUnderTest.isPointOnCurve(pai));
	}

	@Test
	public void testIsPointOnCurve() {

		for (int i = 0; i < 10; i++) {
			// Create valid point
			final EcPoint result = this.curveUnderTest.multiply(this.curveUnderTest.getG(),
					RandomNumberGenerator.generateRandomInteger(this.curveUnderTest.getR()));			
			Assert.assertTrue(this.curveUnderTest.isPointOnCurve(result));
			
			// Create point with invalid y
			final EcPoint invalidY = new EcPoint(result.getX(), result.getY().add(BigInteger.ONE));
			Assert.assertFalse(this.curveUnderTest.isPointOnCurve(invalidY));
			
			// Create point with invalid x
			final EcPoint invalidX = new EcPoint(result.getX().add(BigInteger.ONE), result.getY());
			Assert.assertFalse(this.curveUnderTest.isPointOnCurve(invalidX));

		}
	}

	@Test
	public void testGetOid() {
		Assert.assertEquals(this.curveUnderTest.getOid(), EcCurveBc.createByName(this.curveUnderTest.getName()).getOid());
	}

	@Test
	public void testGetName() {
		Assert.assertEquals(this.curveUnderTest.getName(), EcCurveBc.createByName(this.curveUnderTest.getName()).getName());
	}

}
