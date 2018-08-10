/*
 * Copyright (c) IBM Corporation 2018. All Rights Reserved.
 * Project name: pross
 * This project is licensed under the MIT License, see LICENSE.
 */

package com.ibm.pross.common.util.crypto.ecc;

import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.spec.ECFieldFp;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;

/**
 * This implements most of the non-standard methods, leaving add, multiply, etc.
 * for other implementations to optimize
 * 
 * @author jresch
 */
public class EcCurveImpl implements EcCurve {

	public static final BigInteger TWO = BigInteger.valueOf(2);
	public static final BigInteger THREE = BigInteger.valueOf(3);

	// Coefficients for elliptic curve equation: y^2 = x^3 + ax + b
	private final BigInteger a;
	private final BigInteger b;

	// Prime that defines this curve
	private final BigInteger p;

	// Order of this curve
	private final BigInteger r;

	// Generator for this curve
	private final EcPoint g;

	// Cached point hashers
	private final PointHasher pointHasher;

	/**
	 * Creates an EcCurve from a curve name
	 * 
	 * @param curveName
	 * @return
	 * @throws GeneralSecurityException
	 */
	public static EcCurveImpl createByName(final String curveName) {
		try {
			final AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
			parameters.init(new ECGenParameterSpec(curveName));
			final ECParameterSpec parameterSpec = parameters.getParameterSpec(ECParameterSpec.class);
			return new EcCurveImpl(parameterSpec);
		} catch (GeneralSecurityException e) {
			throw new RuntimeException(e);
		}
	}

	/**
	 * Constructs a EcCurveImpl from an ECParameterSpec
	 * 
	 * Extends EcCurve which supports additional methods
	 * 
	 * @see EcCurve
	 * 
	 * @param parameterSpec
	 */
	public EcCurveImpl(final ECParameterSpec parameterSpec) {
		this(parameterSpec.getCurve().getA(), parameterSpec.getCurve().getB(),
				((ECFieldFp) parameterSpec.getCurve().getField()).getP(), parameterSpec.getOrder(),
				parameterSpec.getGenerator().getAffineX(), parameterSpec.getGenerator().getAffineY());
	}

	// Constructs a curve based on parameters and a generator point
	public EcCurveImpl(BigInteger a, BigInteger b, BigInteger p, BigInteger r, BigInteger gX, BigInteger gY) {

		this.a = a;
		this.b = b;
		this.p = p;
		this.r = r;

		this.g = new EcPoint(gX, gY);

		this.pointHasher = new SwuPointHasher(this);
	}

	// Constructs a curve based on string representations of the integers
	public EcCurveImpl(String aDigits, String bDigits, String pDigits, String rDigits, String gXDigits,
			String gYDigits) {
		this(new BigInteger(aDigits), new BigInteger(bDigits), new BigInteger(pDigits), new BigInteger(rDigits),
				new BigInteger(gXDigits), new BigInteger(gYDigits));
	}

	/**
	 * Add two points together and return the sum
	 * 
	 * @param p
	 * @param q
	 * @return
	 */
	public EcPoint addPoints(final EcPoint p, final EcPoint q) {

		// Handle identity with point at infinity
		if ((p.getX() == q.getX()) || (p.getX() != null && p.getX().equals(q.getX()))
				|| (q.getX() != null && q.getX().equals(p.getX()))) {
			return EcPoint.pointAtInfinity;
		} else if (p.equals(EcPoint.pointAtInfinity)) {
			return q;
		} else if (q.equals(EcPoint.pointAtInfinity)) {
			return p;
		}

		final BigInteger s = (p.getY().subtract(q.getY())).multiply((p.getX().subtract(q.getX()).modInverse(this.p)))
				.mod(this.p);

		final BigInteger x = s.multiply(s).subtract(p.getX().add(q.getX())).mod(this.p);

		final BigInteger y = (s.multiply(p.getX().subtract(x))).subtract(p.getY()).mod(this.p);

		return new EcPoint(x, y);
	}

	/**
	 * Double a point's value (multiply by 2)
	 * 
	 * @param p
	 * @return
	 */
	public EcPoint pointDouble(EcPoint p) {
		final BigInteger s = (THREE.multiply(p.getX()).multiply(p.getX()).add(this.a))
				.multiply(TWO.multiply(p.getY()).modInverse(this.p).mod(this.p));

		final BigInteger x = s.multiply(s).subtract(TWO.multiply(p.getX())).mod(this.p);

		final BigInteger y = (s.multiply(p.getX().subtract(x)).subtract(p.getY())).mod(this.p);

		return new EcPoint(x, y);
	}

	/**
	 * Multiply a point on this curve by a constant
	 * 
	 * @param p
	 * @param n
	 * @return
	 */
	public EcPoint multiply(final EcPoint p, BigInteger n) {
		
		if (p.equals(EcPoint.pointAtInfinity))
		{
			return EcPoint.pointAtInfinity;
		}
		
		EcPoint result = EcPoint.pointAtInfinity;
		EcPoint pPowerOfTwo = p;
		while (n.compareTo(BigInteger.ZERO) > 0) {
			if (n.testBit(0)) // Check if LSB is 1
			{
				if (result.equals(EcPoint.pointAtInfinity))
					result = pPowerOfTwo;
				else
					result = addPoints(result, pPowerOfTwo);
			}
			n = n.shiftRight(1);
			pPowerOfTwo = pointDouble(pPowerOfTwo);
		}
		return result;
	}

	/**
	 * Evaluates the elliptic curve equation given x
	 * 
	 * @param x
	 * @return
	 */
	public BigInteger computeYSquared(BigInteger x) {
		// Get curve parameters
		final BigInteger a = this.getA();
		final BigInteger b = this.getB();
		final BigInteger p = this.getP();

		// Evaluate the equation given x: x^3 + ax + b (mod p)
		final BigInteger ySquared = x.multiply(x).mod(p).multiply(x).mod(p).add(x.multiply(a)).add(b).mod(p);

		return ySquared;
	}

	/**
	 * This function determines whether or not the provided point satisfies the
	 * elliptic curve equation: y^2 = x^3 + ax + b (mod p)
	 * 
	 * It returns true if the point's coordinates satisfy the equation, and
	 * false otherwise
	 * 
	 * @param q
	 * @return
	 */
	public boolean isPointOnCurve(EcPoint q) {
		
		if (q.equals(EcPoint.pointAtInfinity)) {
			return true;
		}
		
		final BigInteger x = q.getX();
		final BigInteger y = q.getY();

		final BigInteger p = getP();
		final BigInteger leftHandSide = y.multiply(y).mod(p);
		final BigInteger rightHandSide = computeYSquared(x);

		return leftHandSide.equals(rightHandSide);
	}

	/**
	 * Return other solution for y^2
	 * 
	 * @param point
	 * @return
	 */
	public EcPoint reflectPoint(final EcPoint point) {
		return new EcPoint(point.getX(), this.getP().subtract(point.getY()));
	}

	public BigInteger getA() {
		return a;
	}

	public BigInteger getB() {
		return b;
	}

	public BigInteger getP() {
		return p;
	}

	public BigInteger getR() {
		return r;
	}

	public EcPoint getG() {
		return g;
	}

	@Override
	public String toString() {
		if (getName() != null) {
			return "Named EcCurve [name=" + getName() + "]";
		} else {
			return "Custm EcCurve [a=" + a + ", b=" + b + ", p=" + p + ", r=" + r + ", g=" + g + "]";
		}
	}

	public String getOid() {
		return CurveLookupMap.getCurveOid(this);
	}

	public String getName() {
		return CurveLookupMap.getCurveName(this);
	}

	public PointHasher getPointHasher() {
		return this.pointHasher;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((a == null) ? 0 : a.hashCode());
		result = prime * result + ((b == null) ? 0 : b.hashCode());
		result = prime * result + ((g == null) ? 0 : g.hashCode());
		result = prime * result + ((p == null) ? 0 : p.hashCode());
		result = prime * result + ((r == null) ? 0 : r.hashCode());
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		EcCurveImpl other = (EcCurveImpl) obj;
		if (a == null) {
			if (other.a != null)
				return false;
		} else if (!a.equals(other.a))
			return false;
		if (b == null) {
			if (other.b != null)
				return false;
		} else if (!b.equals(other.b))
			return false;
		if (g == null) {
			if (other.g != null)
				return false;
		} else if (!g.equals(other.g))
			return false;
		if (p == null) {
			if (other.p != null)
				return false;
		} else if (!p.equals(other.p))
			return false;
		if (r == null) {
			if (other.r != null)
				return false;
		} else if (!r.equals(other.r))
			return false;
		return true;
	}

}
