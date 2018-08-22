/*
 * Copyright (c) IBM Corporation 2018. All Rights Reserved.
 * Project name: pross
 * This project is licensed under the MIT License, see LICENSE.
 */

package com.ibm.pross.common.util.crypto.ecc;

import java.math.BigInteger;
import java.security.spec.ECParameterSpec;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.math.ec.ECPoint;

public class EcCurveBc extends EcCurveImpl {

	private final ECNamedCurveParameterSpec parameterSpec;

	public static EcCurveBc createByName(final String curveName) {
		final ECNamedCurveParameterSpec parameterSpec = ECNamedCurveTable.getParameterSpec(curveName);
		return new EcCurveBc(parameterSpec);
	}

	/**
	 * Constructs a EcCurveBc from an ECParameterSpec
	 * 
	 * Extends EcCurve which supports additional methods
	 * 
	 * @see EcCurve
	 * 
	 * @param parameterSpec
	 */
	public EcCurveBc(final ECNamedCurveParameterSpec parameterSpec) {

		super(parameterSpec.getCurve().getA().toBigInteger(), parameterSpec.getCurve().getB().toBigInteger(),
				parameterSpec.getCurve().getField().getCharacteristic(), parameterSpec.getN(),
				parameterSpec.getG().getAffineXCoord().toBigInteger(),
				parameterSpec.getG().getAffineYCoord().toBigInteger());

		this.parameterSpec = parameterSpec;

	}

	public EcCurveBc(ECParameterSpec params) {
		super(params);
		this.parameterSpec = ECNamedCurveTable.getParameterSpec(this.getName());
	}

	protected ECPoint createECPoint(final EcPoint point) {
		if (point.getX() == null) {
			return parameterSpec.getCurve().getInfinity();
		} else {
			return parameterSpec.getCurve().createPoint(point.getX(), point.getY());
		}
	}

	/**
	 * Uses BC's point addition implementation
	 */
	@Override
	public EcPoint addPoints(final EcPoint p, final EcPoint q) {

		final ECPoint bcP = createECPoint(p);
		final ECPoint bcQ = createECPoint(q);

		final ECPoint sum = bcP.add(bcQ).normalize();

		if (sum.getAffineXCoord() == null) {
			return EcPoint.pointAtInfinity;
		} else {
			return new EcPoint(sum.getAffineXCoord().toBigInteger(), sum.getAffineYCoord().toBigInteger());
		}
	}

	/**
	 * Uses BC's scalar multiplication implementation
	 */
	@Override
	public EcPoint multiply(final EcPoint p, final BigInteger n) {

		final ECPoint bcP = createECPoint(p);

		final ECPoint product = bcP.multiply(n).normalize();

		if (product.getAffineXCoord() == null) {
			// Point at infinity
			return EcPoint.pointAtInfinity;
		} else {
			return new EcPoint(product.getAffineXCoord().toBigInteger(), product.getAffineYCoord().toBigInteger());
		}

	}

	/**
	 * Perform point doubling as "multiply by 2"
	 */
	@Override
	public EcPoint pointDouble(EcPoint p) {
		return this.multiply(p, TWO);
	}

	@Override
	public boolean isPointOnCurve(EcPoint q) {
		if (q.equals(EcPoint.pointAtInfinity)) {
			return true;
		} else {
			final ECPoint bcP = parameterSpec.getCurve().createPoint(q.getX(), q.getY());
			return bcP.isValid();
		}
	}

}
