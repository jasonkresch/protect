/**
 * BNPoint2.java
 *
 * Arithmetic in the group of points on the sextic twist a BN elliptic curve over GF(p^2).
 *
 * A point of an elliptic curve is only meaningful when suitably attached
 * to some curve.  Hence, there must be no public means to create a point
 * by itself (i.e. concrete subclasses of BNPoint2 shall have no public
 * constructor); the proper way to do this is to invoke the factory method
 * pointFactory() of the desired BNCurve subclass.
 *
 * Copyright (C) Paulo S. L. M. Barreto and Geovandro C. C. F. Pereira.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

package com.ibm.pross.common.util.crypto.pairing;

import java.math.BigInteger;
import java.security.SecureRandom;

public class BNPoint2 {

	public static final String differentCurves = "Cannot combine points from different elliptic curves";
	public static final String invalidCPSyntax = "Syntax error in curve point description";
	public static final String pointNotOnCurve = "The given point does not belong to the given elliptic curve";

	/**
	 * The underlying elliptic curve, given by its parameters
	 */
	BNCurve2 E;

	/**
	 * The projective x-coordinate
	 */
	BNField2 x;

	/**
	 * The projective y-coordinate
	 */
	BNField2 y;

	/**
	 * The projective z-coordinate
	 */
	BNField2 z;

	/**
	 * Create an instance of the BNCurve point at infinity on curve E.
	 *
	 * @param E the elliptic curve where the created point is located.
	 */
	BNPoint2(BNCurve2 E) {
		this.E = E;
		/*
		 * the point at infinity is represented as (1, 1, 0) after IEEE Std 1363:2000
		 * (notice that this triple satisfies the projective curve equation y^2 = x^3 +
		 * b.z^6)
		 */
		x = E.Fp2_1;
		y = E.Fp2_1;
		z = E.Fp2_0;
	}

	/**
	 * Create a normalized twist point from given affine coordinates and a curve
	 *
	 * @param E the underlying elliptic curve.
	 * @param x the affine x-coordinate.
	 * @param y the affine y-coordinate.
	 */
	BNPoint2(BNCurve2 E, BNField2 x, BNField2 y) {
		this.E = E;
		this.x = x;
		this.y = y;
		this.z = E.Fp2_1; // normalized
		if (!E.contains(this)) {
			throw new IllegalArgumentException(pointNotOnCurve);
		}
	}

	/**
	 * Create an BNCurve point from a given affine x-coordinate, a y-bit and a curve
	 *
	 * @param E    the underlying elliptic curve.
	 * @param x    the affine x-coordinate.
	 * @param yBit the least significant bit of the y-coordinate.
	 */
	BNPoint2(BNCurve2 E, BNField2 x, int yBit) {
		this.E = E;
		this.x = x;
		if (x.isZero()) {
			throw new IllegalArgumentException(pointNotOnCurve);
		} else {
			this.y = x.cube().add(E.bt).sqrt();
			if (y == null) {
				throw new IllegalArgumentException(pointNotOnCurve);
			}
			if (y.re.testBit(0) != ((yBit & 1) == 1)) {
				y = y.negate();
			}
		}
		this.z = E.Fp2_1; // normalized
		assert (!E.contains(this));
	}

	/**
	 * Create an BNCurve point from a given x-trit, an affine y-coordinate, and a
	 * curve
	 *
	 * @param E     the underlying elliptic curve.
	 * @param xTrit the least significant trit of the x-coordinate.
	 * @param y     the affine y-coordinate.
	 */
	BNPoint2(BNCurve2 E, int xTrit, BNField2 y) {
		this.E = E;
		this.y = y;
		if (y.isZero()) {
			throw new IllegalArgumentException(pointNotOnCurve); // otherwise the curve order would not be prime
		} else {
			this.x = y.square().subtract(E.bt).cbrt();
			if (x == null) {
				throw new IllegalArgumentException(pointNotOnCurve);
			}
			// either x, zeta*x, or zeta^2*x is the desired x-coordinate:
			if (x.re.mod(BNParams._3).intValue() != xTrit) {
				BigInteger zeta = E.E.bn.zeta; // shorthand
				x = x.multiply(zeta);
				if (x.re.mod(BNParams._3).intValue() != xTrit) {
					x = x.multiply(zeta);
					if (x.re.mod(BNParams._3).intValue() != xTrit) {
						throw new IllegalArgumentException(pointNotOnCurve);
					}
				}
			}
		}
		this.z = E.Fp2_1; // normalized
		assert (!E.contains(this));
	}

	/**
	 * Create an BNCurve point from given projective coordinates and a curve.
	 *
	 * @param E the underlying elliptic curve.
	 * @param x the affine x-coordinate.
	 * @param y the affine y-coordinate.
	 * @param z the affine z-coordinate.
	 */
	private BNPoint2(BNCurve2 E, BNField2 x, BNField2 y, BNField2 z) {
		this.E = E;
		this.x = x;
		this.y = y;
		this.z = z;
	}

	/**
	 * Create a clone of a given point.
	 *
	 * @param Q the point to be cloned.
	 */
	public BNPoint2(BNPoint2 Q) {
		this.E = Q.E;
		this.x = Q.x;
		this.y = Q.y;
		this.z = Q.z;
	}

	/*
	 * performing arithmetic operations on elliptic curve points generally implies
	 * knowing the nature of these points (more precisely, the nature of the finite
	 * field to which their coordinates belong), hence they are done by the
	 * underlying elliptic curve.
	 */

	/**
	 * Check whether this is the point at infinity (i.e. the BNCurve group zero
	 * element).
	 *
	 * @return true if this is the point at infinity, otherwise false.
	 */
	public boolean isZero() {
		return z.isZero();
	}

	/**
	 * Compare this point to a given object.
	 *
	 * @param Q the elliptic curve point to be compared to this.
	 *
	 * @return true if this point and Q are equal, otherwise false.
	 */
	public boolean equals(Object Q) {
		if (!(Q instanceof BNPoint2) || !this.isOnSameCurve((BNPoint2) Q)) {
			return false;
		}
		BNPoint2 P = (BNPoint2) Q;
		if (z.isZero() || P.isZero()) {
			return z.equals(P.z);
		} else {
			// x/z^2 = x'/z'^2 <=> x*z'^2 = x'*z^2.
			// y/z^3 = y'/z'^3 <=> y*z'^3 = y'*z^3,
			BNField2 z2 = z.square(), z3 = z.multiply(z2), pz2 = P.z.square(), pz3 = P.z.multiply(pz2);
			return x.multiply(pz2).equals(P.x.multiply(z2)) && y.multiply(pz3).equals(P.y.multiply(z3));
		}
	}

	/**
	 * Check whether Q lays on the same curve as this point.
	 *
	 * @param Q an elliptic curve point.
	 *
	 * @return true if Q lays on the same curve as this point, otherwise false.
	 */
	public boolean isOnSameCurve(BNPoint2 Q) {
		return E.E.bn == Q.E.E.bn; // singleton comparison
	}

	/**
	 * Compute a random point on the same curve as this.
	 *
	 * @param rand a cryptographically strong pseudo-random number generator.
	 *
	 * @return a random point on the same curve as this.
	 */
	public BNPoint2 randomize(SecureRandom rand) {
		return E.pointFactory(rand);
	}

	/**
	 * Normalize this point.
	 *
	 * @return a normalized point equivalent to this.
	 */
	public BNPoint2 normalize() {
		if (z.isZero() || z.isOne()) {
			return this; // already normalized
		}
		BNField2 zinv = z.inverse(), zinv2 = zinv.square(), zinv3 = zinv.multiply(zinv2);
		return new BNPoint2(E, x.multiply(zinv2), y.multiply(zinv3), E.Fp2_1);
	}

	/**
	 * Compute -this.
	 *
	 * @return -this.
	 */
	public BNPoint2 negate() {
		return new BNPoint2(E, x, y.negate(), z);
	}

	/**
	 * Check if a point equals -this.
	 */
	public boolean opposite(BNPoint2 P) {
		return this.equals(P.negate());
	}

	/**
	 * Compute this + Q.
	 *
	 * @return this + Q.
	 *
	 * @param Q an elliptic curve point.
	 */
	public BNPoint2 add(BNPoint2 Q) {
		assert (isOnSameCurve(Q));
		if (this.isZero()) {
			return Q;
		}
		if (Q.isZero()) {
			return this;
		}
		// *
		// EFD addition formulas:
		// <http://www.hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-0.html>
		BNField2 Fp2_1 = E.E.bn.Fp2_1;
		BNField2 X1 = x, Y1 = y, Z1 = z, X2 = Q.x, Y2 = Q.y, Z2 = Q.z, Z1Z1 = Fp2_1, Z2Z2 = Fp2_1, U1 = x, U2 = Q.x,
				S1 = y, S2 = Q.y, H, I, J, R, V, X3, Y3, Z3;
		boolean Z1is1 = Z1.isOne();
		boolean Z2is1 = Z2.isOne();
		if (!Z1is1) {
			Z1Z1 = Z1.square(); // Z1Z1 = Z1^2
			U2 = X2.multiply(Z1Z1); // U2 = X2*Z1Z1
			S2 = Y2.multiply(Z1).multiply(Z1Z1); // S2 = Y2*Z1*Z1Z1
		}
		if (!Z2is1) {
			Z2Z2 = Z2.square(); // Z2Z2 = Z2^2
			U1 = X1.multiply(Z2Z2); // U1 = X1*Z2Z2
			S1 = Y1.multiply(Z2).multiply(Z2Z2); // S1 = Y1*Z2*Z2Z2
		}
		if (U1.equals(U2)) {
			if (S1.equals(S2)) {
				return twice(1);
			} else {
				return E.infinity;
			}
		}
		H = U2.subtract(U1); // H = U2-U1
		I = H.twice(1).square(); // I = (2*H)^2
		J = H.multiply(I); // J = H*I
		R = S2.subtract(S1).twice(1); // r = 2*(S2-S1)
		V = U1.multiply(I); // V = U1*I
		X3 = R.square().subtract(J).subtract(V.twice(1)); // X3 = r^2-J-2*V
		Y3 = R.multiply(V.subtract(X3)).subtract(S1.multiply(J).twice(1)); // Y3 = r*(V-X3)-2*S1*J
		if (Z2is1) {
			if (Z1is1) {
				Z3 = H.twice(1); // Z3 = 2*H
			} else {
				Z3 = Z1.multiply(H).twice(1); // Z3 = ((Z1+1)^2-Z1Z1-1)*H
			}
		} else {
			if (Z1is1) {
				Z3 = Z2.multiply(H).twice(1); // Z3 = ((1+Z2)^2-1-Z2Z2)*H
			} else {
				Z3 = Z1.add(Z2).square().subtract(Z1Z1).subtract(Z2Z2).multiply(H);// Z3 = ((Z1+Z2)^2-Z1Z1-Z2Z2)*H
			}
		}
		return new BNPoint2(E, X3, Y3, Z3);
		// */
		/*
		 * // P1363 section A.10.5 BNField2 t1, t2, t3, t4, t5, t6, t7, M; t1 = x; t2 =
		 * y; t3 = z; t4 = Q.x; t5 = Q.y; t6 = Q.z; if (!t6.isOne()) { t7 = t6.square();
		 * // t7 = z1^2 // u0 = x0.z1^2 t1 = t1.multiply(t7); // s0 = y0.z1^3 =
		 * y0.z1^2.z1 t2 = t2.multiply(t7).multiply(t6); } if (!t3.isOne()) { t7 =
		 * t3.square(); // t7 = z0^2 // u1 = x1.z0^2 t4 = t4.multiply(t7); // s1 =
		 * y1.z0^3 = y1.z0^2.z0 t5 = t5.multiply(t7).multiply(t3); } // W = u0 - u1 t7 =
		 * t1.subtract(t4); // R = s0 - s1 M = t2.subtract(t5); if (t7.isZero()) {
		 * return M.isZero() ? Q.twice(1) : E.infinity; } // T = u0 + u1 t1 =
		 * t1.add(t4); // M = s0 + s1 t2 = t2.add(t5); // z2 = z0.z1.W if (!t6.isOne())
		 * { t3 = t3.multiply(t6); } t3 = t3.multiply(t7); // x2 = R^2 - T.W^2 t5 =
		 * t7.square(); // t5 = W^2 t6 = t1.multiply(t5); // t6 = T.W^2 t1 =
		 * M.square().subtract(t6); // 2.y2 = (T.W^2 - 2.x2).R - M.W^2.W t2 =
		 * t6.subtract(t1.twice(1)).multiply(M).subtract(t2.multiply(t5).multiply(t7)).
		 * halve(); // lambda = (Q.y - T.y)/(Q.x - T.x) // Q.Z = 1 // = (y1 - y0/z0^3) /
		 * (x1 - x0/z0^2) // = (y1*z0^3 - y0) / (x1*z0^3 - x0*z0) // = (y0 - y1*z0^3) /
		 * z0*(x0 - x1*z0^2) return new BNPoint2(E, t1, t2, t3); //
		 */
	}

	/**
	 * Left-shift this point by a given distance n, i.e. compute (2^^n)*this.
	 *
	 * @param n the shift amount.
	 *
	 * @return (2^^n)*this.
	 */
	public BNPoint2 twice(int n) {
		// EDF doubling formulas:
		// <http://www.hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-0.html#doubling-dbl-2009-l>
		// <http://www.hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-0.html#doubling-mdbl-2007-bl>
		BNField2 A, B, C, S, M, X = x, Y = y, Z = z;
		while (n-- > 0) {
			A = X.square(); // A = X1^2
			B = Y.square(); // B = Y1^2
			C = B.square(); // C = B^2
			S = X.add(B).square().subtract(A).subtract(C).twice(1); // S = 2*((X1+B)^2-A-C)
			M = A.multiply(3); // M = 3*A
			X = M.square().subtract(S.twice(1)); // X3 = M^2-2*S
			Z = Y.multiply(Z).twice(1); // Z3 = 2*Y1*Z1
			Y = M.multiply(S.subtract(X)).subtract(C.twice(3)); // Y3 = M*(S-X3)-8*C
		}
		return new BNPoint2(E, X, Y, Z);
	}

	/**
	 * Compute k*this
	 *
	 * This method implements the quaternary window multiplication algorithm.
	 *
	 * Reference:
	 *
	 * Alfred J. Menezes, Paul C. van Oorschot, Scott A. Vanstone, "Handbook of
	 * Applied Cryptography", CRC Press (1997), section 14.6 (Exponentiation),
	 * algorithm 14.82
	 *
	 * @param k scalar by which this point is to be multiplied
	 *
	 * @return k*this
	 */
	// *
	public BNPoint2 multiply(BigInteger k) {
		BNPoint2 P = this.normalize();
		if (k.signum() < 0) {
			k = k.negate();
			P = P.negate();
		}

		byte[] e = k.toByteArray();
		BNPoint2[] mP = new BNPoint2[16];
		mP[0] = E.infinity;
		mP[1] = P;
		for (int i = 1; i <= 7; i++) {
			mP[2 * i] = mP[i].twice(1);
			mP[2 * i + 1] = mP[2 * i].add(P);
		}
		BNPoint2 A = E.infinity;
		for (int i = 0; i < e.length; i++) {
			int u = e[i] & 0xff;
			A = A.twice(4).add(mP[u >>> 4]).twice(4).add(mP[u & 0xf]);
		}
		return A.normalize();
	}
	// */

	/**
	 * Compute k*this
	 *
	 * @param k scalar by which this point is to be multiplied
	 *
	 * @return k*this
	 *
	 *         This method implements the GLV strategy.
	 *
	 *         Consider the Galbraith-Scott reduced basis for the BN(u) lattice,
	 *         i.e. B = [ u + 1 u u -2*u] [ 2*u + 1 -u -u - 1 -u] [ 2*u 2*u + 1 2*u
	 *         + 1 2*u + 1] [ u - 1 4*u + 2 -2*u + 1 u - 1]
	 *
	 *         The adjoint of this matrix is: Adj(B) = [ -6*u^2 - 9*u - 3 -36*u^3 -
	 *         24*u^2 - 3*u -18*u^3 - 12*u^2 - 3*u 6*u^2 + 3*u] [ -18*u^3 + 6*u + 1
	 *         18*u^3 - 6*u - 2 -3*u - 1 -18*u^3 - 18*u^2 - 6*u - 1] [-18*u^3 -
	 *         30*u^2 - 15*u - 3 18*u^3 + 24*u^2 + 15*u + 3 -18*u^3 - 6*u^2 18*u^3 +
	 *         12*u^2 + 3*u] [ 36*u^3 + 36*u^2 + 15*u + 2 -18*u^2 - 9*u - 1 -18*u^3
	 *         - 18*u^2 - 9*u - 2 3*u + 1]
	 *
	 *         Clearly B*Adj(B) = -3*n*I, so that B^{-1} = (-3*n)^{-1}*Adj(B). The
	 *         GLV method for this basis requires the vector w = Round((k, 0, 0,
	 *         0)*B^{-1}) = Round(k*(-3*n)^{-1}*(1, 0, 0, 0)*Adj(B)) =
	 *         Round(k*(6*u^2 + 9*u + 3, 36*u^3 + 24*u^2 + 3*u, 18*u^3 + 12*u^2 +
	 *         3*u, -6*u^2 - 3*u)/(3*n)) = Round(k*(2*u^2 + 3*u + 1, 12*u^3 + 8*u^2
	 *         + u, 6*u^3 + 4*u^2 + u, -2*u^2 - u)/n) = Round(k*lat[0..3]/n).
	 *
	 *         Roundings can be carried out with integer arithmetic only. Let the
	 *         rounding operand be x/n, and let h = n div 2. If x mod n <= h, then
	 *         Round(x/n) = x div n, otherwise Round(x/n) = (x div n) + 1.
	 */
	/*
	 * public BNPoint2 multiply(BigInteger k) { BNParams bn = E.E.bn; BNPoint2 P =
	 * this.normalize(); if (k.signum() < 0) { P = P.negate(); k = k.negate(); } //k
	 * = k.mod(bn.n); BigInteger halfn = bn.n.shiftRight(1); BigInteger[] w = new
	 * BigInteger[4]; for (int i = 0; i < 4; i++) { w[i] = k.multiply(bn.latInv[i]);
	 * if (w[i].mod(bn.n).compareTo(halfn) <= 0) { w[i] = w[i].divide(bn.n); } else
	 * { w[i] = w[i].divide(bn.n).add(_1); } } BigInteger[] u = new BigInteger[4];
	 * for (int j = 0; j < 4; j++) { u[j] = _0; for (int i = 0; i < 4; i++) { u[j] =
	 * u[j].add(w[i].multiply(bn.latRed[i][j])); } u[j] = u[j].negate(); } u[0] =
	 * u[0].add(k); BNPoint2 Q = P.frobex(1); BNPoint2 R = P.frobex(2); BNPoint2 S =
	 * P.frobex(3); //BNPoint2 Q =
	 * P.multiply0(bn.t.subtract(_1)).normalize();//P.frobex(1); //BNPoint2 R =
	 * Q.multiply0(bn.t.subtract(_1)).normalize();//P.frobex(2); //BNPoint2 S =
	 * R.multiply0(bn.t.subtract(_1)).normalize();//P.frobex(3);
	 * 
	 * //System.out.println("k  = " + k.mod(bn.n)); //System.out.println("k' = " +
	 * u[0].add(u[1].multiply(bn.t.subtract(_1))).add(u[2].multiply(bn.t.subtract(_1
	 * ).pow(2))).add(u[3].multiply(bn.t.subtract(_1).pow(3))).mod(bn.n));
	 * //System.out.println("k*P    = " + P.multiply0(k.mod(bn.n)).normalize());
	 * //System.out.println("k'*P   = " +
	 * P.multiply0(u[0].add(u[1].multiply(bn.t.subtract(_1))).add(u[2].multiply(bn.t
	 * .subtract(_1).pow(2))).add(u[3].multiply(bn.t.subtract(_1).pow(3))).mod(bn.n)
	 * ).normalize()); //System.out.println("k'*P   = " +
	 * P.multiply0(u[0]).add(P.multiply0(u[1].multiply(bn.t.subtract(_1)).add(u[2].
	 * multiply(bn.t.subtract(_1).pow(2))).add(u[3].multiply(bn.t.subtract(_1).pow(3
	 * ))).mod(bn.n))).normalize()); //System.out.println("k'*P   = " +
	 * P.multiply0(u[0]).add( P.multiply0(
	 * u[1].multiply(bn.t.subtract(_1)).mod(bn.n).add(u[2].multiply(bn.t.subtract(_1
	 * ).pow(2)).mod(bn.n)).add(u[3].multiply(bn.t.subtract(_1).pow(3)).mod(bn.n)).
	 * mod(bn.n) ) ).normalize()); //System.out.println("k'*P   = " +
	 * P.multiply0(u[0]).normalize()
	 * .add(P.multiply0(u[1]).multiply0(bn.t.subtract(_1)).normalize())
	 * .add(P.multiply0(u[2]).multiply0(bn.t.subtract(_1)).multiply0(bn.t.subtract(
	 * _1)).normalize())
	 * .add(P.multiply0(u[3]).multiply0(bn.t.subtract(_1)).multiply0(bn.t.subtract(
	 * _1)).multiply0(bn.t.subtract(_1)).normalize()) .normalize());
	 * //System.out.println("k'*P   = " + P.multiply0(u[0]).normalize()
	 * .add(P.multiply0(bn.t.subtract(_1)).multiply0(u[1]).normalize())
	 * .add(P.multiply0(bn.t.subtract(_1)).multiply0(bn.t.subtract(_1)).multiply0(u[
	 * 2]).normalize())
	 * .add(P.multiply0(bn.t.subtract(_1)).multiply0(bn.t.subtract(_1)).multiply0(bn
	 * .t.subtract(_1)).multiply0(u[3]).normalize()) .normalize());
	 * //System.out.println("k'*P   = " +
	 * P.multiply0(u[0]).add(Q.multiply0(u[1])).add(R.multiply0(u[2])).add(S.
	 * multiply0(u[3])).normalize()); //System.exit(0); return simultaneous(u[0], P,
	 * u[1], Q, u[2], R, u[3], S); } //
	 */

	/**
	 * Compute ks*this + kr*Y. This is useful in the verification part of several
	 * signature algorithms, and (hopely) faster than two scalar multiplications.
	 *
	 * @param ks scalar by which this point is to be multiplied.
	 * @param kr scalar by which Y is to be multiplied.
	 * @param Y  a curve point.
	 *
	 * @return ks*this + kr*Y
	 */
	public BNPoint2 simultaneous(BigInteger ks, BigInteger kr, BNPoint2 Y) {
		assert (isOnSameCurve(Y));
		BNPoint2[] hV = new BNPoint2[16];
		BNPoint2 P = this.normalize();
		Y = Y.normalize();
		if (ks.signum() < 0) {
			ks = ks.negate();
			P = P.negate();
		}
		if (kr.signum() < 0) {
			kr = kr.negate();
			Y = Y.negate();
		}
		hV[0] = E.infinity;
		hV[1] = P;
		hV[2] = Y;
		hV[3] = P.add(Y);
		for (int i = 4; i < 16; i += 4) {
			hV[i] = hV[i >> 2].twice(1);
			hV[i + 1] = hV[i].add(hV[1]);
			hV[i + 2] = hV[i].add(hV[2]);
			hV[i + 3] = hV[i].add(hV[3]);
		}
		int t = Math.max(kr.bitLength(), ks.bitLength());
		BNPoint2 R = E.infinity;
		for (int i = (((t + 1) >> 1) << 1) - 1; i >= 0; i -= 2) {
			int j = (kr.testBit(i) ? 8 : 0) | (ks.testBit(i) ? 4 : 0) | (kr.testBit(i - 1) ? 2 : 0)
					| (ks.testBit(i - 1) ? 1 : 0);
			R = R.twice(2).add(hV[j]);
		}
		return R.normalize();
	}

	public BNPoint2 simultaneous(BigInteger kP, BNPoint2 P, BigInteger kQ, BNPoint2 Q, BigInteger kR, BNPoint2 R,
			BigInteger kS, BNPoint2 S) {
		BNPoint2[] hV = new BNPoint2[16];
		P = P.normalize();
		if (kP.signum() < 0) {
			kP = kP.negate();
			P = P.negate();
		}
		Q = Q.normalize();
		if (kQ.signum() < 0) {
			kQ = kQ.negate();
			Q = Q.negate();
		}
		R = R.normalize();
		if (kR.signum() < 0) {
			kR = kR.negate();
			R = R.negate();
		}
		S = S.normalize();
		if (kS.signum() < 0) {
			kS = kS.negate();
			S = S.negate();
		}
		hV[0] = E.infinity;
		hV[1] = P;
		hV[2] = Q;
		hV[4] = R;
		hV[8] = S;
		for (int i = 2; i < 16; i <<= 1) {
			for (int j = 1; j < i; j++) {
				hV[i + j] = hV[i].add(hV[j]);
			}
		}
		int t = Math.max(Math.max(kP.bitLength(), kQ.bitLength()), Math.max(kR.bitLength(), kS.bitLength()));
		BNPoint2 V = E.infinity;
		for (int i = t - 1; i >= 0; i--) {
			int j = (kS.testBit(i) ? 8 : 0) | (kR.testBit(i) ? 4 : 0) | (kQ.testBit(i) ? 2 : 0)
					| (kP.testBit(i) ? 1 : 0);
			V = V.twice(2).add(hV[j]);
		}
		return V.normalize();
	}

	public BNPoint2 frobex(int k) {
		if (!z.isOne()) {
			throw new RuntimeException("Logic Error!");
		}
		BNParams bn = E.E.bn;
		switch (k) {
		case 1:
			return (bn.b == 3)
					? new BNPoint2(E, x.multiplyI().conjugate().multiply(bn.zeta),
							y.multiplyV().conjugate().multiply(bn.zeta0sigma), z)
					: new BNPoint2(E, x.conjugate().multiplyI().multiply(bn.zeta),
							y.conjugate().multiplyV().multiply(bn.zeta1sigma), z);
		case 2:
			return new BNPoint2(E, x.multiply(bn.zeta1).negate(), y.negate(), z);
		case 3:
			return (bn.b == 3)
					? new BNPoint2(E, x.multiplyI().conjugate(),
							y.multiplyV().conjugate().multiply(bn.zeta0sigma).negate(), z)
					: new BNPoint2(E, x.conjugate().multiplyI(),
							y.conjugate().multiplyV().multiply(bn.zeta1sigma).negate(), z);
		default:
			return null;
		}
	}

	public String toString() {
		return "[" + x + " : " + y + " : " + z + "]";
	}

}
