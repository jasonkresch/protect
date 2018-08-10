/*
 * Copyright (c) IBM Corporation 2018. All Rights Reserved.
 * Project name: pross
 * This project is licensed under the MIT License, see LICENSE.
 */

package com.ibm.pross.common.util.crypto.ecc;

import java.util.Arrays;
import java.util.Collection;
import java.util.Random;

import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Ignore;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

@RunWith(Parameterized.class)
public class PointHasherPerformanceTest {

	@Parameters(name = "{0}")
	public static Collection<Object> data() {
		return Arrays.asList(new Object[] { EcCurve.secp256r1, EcCurve.secp384r1, EcCurve.secp521r1 });
	}

	private final EcCurve curveUnderTest;

	@BeforeClass
	public static void setupBeforeClass() {
		EcCurve.secp256r1.getPointHasher().hashToCurve("init");
	}

	public PointHasherPerformanceTest(EcCurve curveUnderTest) {
		this.curveUnderTest = curveUnderTest;
	}

	@Ignore
	@Test
	public void testRandomStringsWithNondeterministicTimePointHasherCorrectness() {

		final PointHasher pointHasher = this.curveUnderTest.getPointHasher();

		byte[] input = new byte[16];
		final Random random = new Random();

		for (int i = 0; i < 10000; i++) {
			random.nextBytes(input);
			final EcPoint point = pointHasher.hashToCurve(input);
			Assert.assertTrue(this.curveUnderTest.isPointOnCurve(point));
		}
	}

	@Ignore
	@Test
	public void testRandomStringsWithNondeterministicTimePointHasher() {

		final PointHasher pointHasher = this.curveUnderTest.getPointHasher();

		byte[] input = new byte[16];
		final Random random = new Random();

		for (int i = 0; i < 10000; i++) {
			random.nextBytes(input);
			pointHasher.hashToCurve(input);
		}
	}

	@Ignore
	@Test
	public void testRandomStringsWithConstantTimePointHasher() {

		final PointHasher pointHasher = this.curveUnderTest.getPointHasher();

		byte[] input = new byte[16];
		final Random random = new Random();

		for (int i = 0; i < 10000; i++) {
			random.nextBytes(input);
			pointHasher.hashToCurve(input);
		}
	}

	@Test
	public void testRandomStringsWithConstantTimePointHasherCorrectness() {

		final PointHasher pointHasher = this.curveUnderTest.getPointHasher();

		byte[] input = new byte[16];
		final Random random = new Random();

		for (int i = 0; i < 10000; i++) {
			random.nextBytes(input);
			final EcPoint point = pointHasher.hashToCurve(input);
			Assert.assertTrue(this.curveUnderTest.isPointOnCurve(point));
		}
	}
}
