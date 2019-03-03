/**
 * BNCurve.java
 *
 * Barreto-Naehrig (BN) pairing-friendly elliptic curves.
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

public class BNCurve {

	/**
	 * Convenient BigInteger constants
	 */
	static final BigInteger _1 = BigInteger.valueOf(1L), _2 = BigInteger.valueOf(2L), _3 = BigInteger.valueOf(3L);

	/**
	 * BN parameters (singleton)
	 */
	BNParams bn;

	/**
	 * Coefficient of the elliptic curve equation
	 */
	BigInteger b;

	/**
	 * The base point of large prime order n
	 */
	BNPoint G;

	/**
	 * Prime curve order
	 */
	BigInteger n;

	/**
	 * The point at infinity
	 */
	BNPoint infinity;

	/**
	 * Multiples of the base point G by simple multiples of powers of 16.
	 */
	protected BNPoint[][] pp16G;

	/**
	 * Build the standard BN curve BN(u): y^2 = x^3 + b.
	 *
	 * @param bn BN parameters of the curve
	 *
	 * @return the desired curve, or null if the given index does not define
	 *         suitable parameters
	 */
	public BNCurve(BNParams bn) {
		this.bn = bn;
		b = (bn.b == 3) ? _3 : _2; // standard curve
		infinity = new BNPoint(this); // caveat: must be set *after* p but *before* G!
		G = (bn.b == 3) ? new BNPoint(this, _1, _2) : new BNPoint(this, _1.negate(), _1); // standard curve
		/*
		 * System.out.println("G = " + G); System.out.println("n*G = " + G.multiply(n));
		 * //
		 */
		assert (G.multiply(bn.n).isZero());
		/*
		 * pp16G = new BNPoint[(bn.n.bitLength() + 3)/4][16]; pp16Gserial = new
		 * byte[(bn.n.bitLength() + 3)/4][16][]; long elapsed =
		 * -System.currentTimeMillis(); for (int qqq = 0; qqq < 1; qqq++) { BNPoint[]
		 * pp16Gi = pp16G[0]; pp16Gi[0] = infinity; pp16Gi[1] = G; for (int i = 1, j =
		 * 2; i <= 7; i++, j += 2) { pp16Gi[j ] = pp16Gi[i].twice(1).normalize();
		 * pp16Gi[j+1] = pp16Gi[j].add(G).normalize(); } for (int i = 1; i <
		 * pp16G.length; i++) { BNPoint[] pp16Gh = pp16Gi; pp16Gi = pp16G[i]; pp16Gi[0]
		 * = pp16Gh[0]; for (int j = 1; j < 16; j++) { pp16Gi[j] =
		 * pp16Gh[j].twice(4).normalize(); } } } elapsed += System.currentTimeMillis();
		 * System.out.println("pp16G construction = " + elapsed); //
		 */
		// System.exit(0);
		/*
		 * System.out.println("========"); for (int i = 0; i < pp16G.length; i++) { for
		 * (int j = 0; j < pp16G[i].length; j++) { System.out.println("pp16G[" + i +
		 * "][" + j + "] = " + pp16G[i][j]); } } System.exit(0); //
		 */
		/*
		 * for (int i = 0; i < pp16G.length; i++) { for (int j = 0; j < pp16G[i].length;
		 * j++) { pp16Gserial[i][j] = pp16G[i][j].toByteArray(BNPoint.EXPANDED); } }
		 * elapsed = -System.currentTimeMillis(); for (int qqq = 0; qqq < 1; qqq++) {
		 * for (int i = 0; i < pp16G.length; i++) { for (int j = 0; j < pp16G[i].length;
		 * j++) { pp16G[i][j] = new BNPoint(this, pp16Gserial[i][j]); } } } elapsed +=
		 * System.currentTimeMillis(); System.out.println("pp16G deserialization = " +
		 * elapsed); //
		 */
	}

	/**
	 * Get a random nonzero point on this curve, given a fixed base point.
	 *
	 * @param rand a cryptographically strong PRNG
	 *
	 * @return a random nonzero point on this curve
	 */
	public BNPoint pointFactory(SecureRandom rand) {
		BigInteger x, y;
		do {
			x = new BigInteger(2 * bn.p.bitLength(), rand).mod(bn.p);
			y = bn.sqrt(x.multiply(x).multiply(x).add(b));
		} while (y == null);
		return new BNPoint(this, x, y);
	}

	public BNParams getCurveParams() {
		return bn;
	}

	public BigInteger getOrder() {
		return n;
	}

	public BigInteger getCurveCoefficient() {
		return b;
	}

	public BNPoint getCurveGenerator() {
		return G;
	}

	/**
	 * Check whether this curve contains a given point (i.e. whether that point
	 * satisfies the curve equation)
	 *
	 * @param P the point whose pertinence or not to this curve is to be determined
	 *
	 * @return true if this curve contains P, otherwise false
	 */
	public boolean contains(BNPoint P) {
		if (P.E != this) {
			return false;
		}
		// check the projective equation y^2 = x^3 + b*z^6,
		// i.e. x*x^2 + b*z^2*(z^2)^2 - y^2 = 0
		// (the computation below never uses intermediate values larger than 3p^2)
		BigInteger x = P.x, y = P.y, z = P.z, x2 = x.multiply(x).mod(bn.p), z2 = z.multiply(z).mod(bn.p),
				z4 = z2.multiply(z2).mod(bn.p), br = b.multiply(z2).mod(bn.p);
		return x.multiply(x2).add(br.multiply(z4)).subtract(y.multiply(y)).mod(bn.p).signum() == 0;
	}

	/*
	 * public BNPoint kG(BigInteger k) { k = k.mod(bn.n); BNPoint A = infinity; for
	 * (int i = 0, w = 0; i < pp16G.length; i++, w >>>= 4) { if ((i & 7) == 0) { w =
	 * k.intValue(); k = k.shiftRight(32); } A = A.add(pp16G[i][w & 0xf]); } return
	 * A; } //
	 */

	public String toString() {
		return "BN(" + bn.u + "): y^2 = x^3 + " + b;
	}

}
