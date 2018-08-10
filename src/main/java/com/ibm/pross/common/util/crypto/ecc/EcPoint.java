/*
 * Copyright (c) IBM Corporation 2018. All Rights Reserved.
 * Project name: pross
 * This project is licensed under the MIT License, see LICENSE.
 */

package com.ibm.pross.common.util.crypto.ecc;

import java.io.Serializable;
import java.math.BigInteger;

public class EcPoint implements Serializable {
	
	private static final long serialVersionUID = 1898156347028500202L;
	
	private final BigInteger x;
	private final BigInteger y;

	private EcPoint()
	{
		this.x = null;
		this.y = null;
	}
	
	public static EcPoint pointAtInfinity = new EcPoint();
	
	/**
	 * Finds one of the solutions for y given x, if x is a valid x-coordinate on
	 * the curve. Otherwise, this method throws an illegal argument exception.
	 * The other solution is the reflected version of this point which can be
	 * obtained from EcCurve.reflectPoint().
	 * 
	 * @param x
	 * @param curve
	 */
	public EcPoint(final BigInteger x, final EcCurve curve) {
		
		final BigInteger yy = curve.computeYSquared(x);
		
		// This only gets a valid result if y is a quad residue
		final BigInteger y = curve.getPointHasher().squareRoot(yy);
		final EcPoint candidatePoint = new EcPoint(x, y);
		
		if (curve.isPointOnCurve(candidatePoint)) {
			this.x = x;
			this.y = y;
		} else {
			throw new IllegalArgumentException("X coordinate is not on curve!");
		}
	}

	public EcPoint(final String xDigits, final String yDigits) {
		this(new BigInteger(xDigits), new BigInteger(yDigits));
	}

	public EcPoint(BigInteger x, BigInteger y) {
		this.x = x;
		this.y = y;
	}

	public BigInteger getX() {
		return x;
	}

	public BigInteger getY() {
		return y;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((x == null) ? 0 : x.hashCode());
		result = prime * result + ((y == null) ? 0 : y.hashCode());
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		EcPoint other = (EcPoint) obj;
		if (x == null) {
			if (other.x != null)
				return false;
		} else if (!x.equals(other.x))
			return false;
		if (y == null) {
			if (other.y != null)
				return false;
		} else if (!y.equals(other.y))
			return false;
		return true;
	}

	@Override
	public String toString() {
		return "EcPoint [x=" + x + ", y=" + y + "]";
	}

}
