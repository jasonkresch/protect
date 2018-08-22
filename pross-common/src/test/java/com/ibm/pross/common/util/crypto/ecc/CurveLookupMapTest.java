/*
 * Copyright (c) IBM Corporation 2018. All Rights Reserved.
 * Project name: pross
 * This project is licensed under the MIT License, see LICENSE.
 */

package com.ibm.pross.common.util.crypto.ecc;

import java.math.BigInteger;

import org.junit.Assert;
import org.junit.Test;

public class CurveLookupMapTest {

	@Test
	public void testGetSecp256r1ByName() {
		Assert.assertEquals(EcCurve.secp256r1, CurveLookupMap.getCurveByName("secp256r1"));
	}

	@Test
	public void testGetSecp384r1ByName() {
		Assert.assertEquals(EcCurve.secp384r1, CurveLookupMap.getCurveByName("secp384r1"));
	}

	@Test
	public void testGetSecp512r1ByName() {
		Assert.assertEquals(EcCurve.secp521r1, CurveLookupMap.getCurveByName("secp521r1"));
	}

	@Test
	public void testGetSecp256r1ByOid() {
		Assert.assertEquals(EcCurve.secp256r1, CurveLookupMap.getCurveByOid("1.2.840.10045.3.1.7"));
	}

	@Test
	public void testGetSecp384r1ByOid() {
		Assert.assertEquals(EcCurve.secp384r1, CurveLookupMap.getCurveByOid("1.3.132.0.34"));
	}

	@Test
	public void testGetSecp512r1ByOid() {
		Assert.assertEquals(EcCurve.secp521r1, CurveLookupMap.getCurveByOid("1.3.132.0.35"));
	}

	@Test
	public void testNotFoundByOid() {
		Assert.assertNull(CurveLookupMap.getCurveByOid("1.1.1"));
	}

	@Test
	public void testNotFoundByName() {
		Assert.assertNull(CurveLookupMap.getCurveByOid("none"));
	}

	@Test
	public void testGetSecp256r1Name() {
		Assert.assertEquals("secp256r1", CurveLookupMap.getCurveName(EcCurve.secp256r1));
	}

	@Test
	public void testGetSecp384r1Name() {
		Assert.assertEquals("secp384r1", CurveLookupMap.getCurveName(EcCurve.secp384r1));
	}

	@Test
	public void testGetSecp521r1Name() {
		Assert.assertEquals("secp521r1", CurveLookupMap.getCurveName(EcCurve.secp521r1));
	}

	@Test
	public void testGetSecp256r1Oid() {
		Assert.assertEquals("1.2.840.10045.3.1.7", CurveLookupMap.getCurveOid(EcCurve.secp256r1));
	}

	@Test
	public void testGetSecp384r1Oid() {
		Assert.assertEquals("1.3.132.0.34", CurveLookupMap.getCurveOid(EcCurve.secp384r1));
	}

	@Test
	public void testGetSecp512r1Oid() {
		Assert.assertEquals("1.3.132.0.35", CurveLookupMap.getCurveOid(EcCurve.secp521r1));
	}

	@Test
	public void testNotFoundOid() {
		EcCurve madeUpCurve = new EcCurveImpl(BigInteger.ONE, BigInteger.ONE, PointHasher.THREE, BigInteger.ONE, BigInteger.ONE,BigInteger.ONE);
		Assert.assertNull(CurveLookupMap.getCurveOid(madeUpCurve));
	}

	@Test
	public void testNotFoundName() {
		EcCurve madeUpCurve = new EcCurveImpl(BigInteger.ONE, BigInteger.ONE, PointHasher.THREE, BigInteger.ONE, BigInteger.ONE,BigInteger.ONE);
		Assert.assertNull(CurveLookupMap.getCurveName(madeUpCurve));
	}

}
