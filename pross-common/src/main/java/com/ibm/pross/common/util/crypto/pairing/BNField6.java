/**
 * BNField6.java
 *
 * Arithmetic in the finite extension field GF(p^6) with p = 3 (mod 4).
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

public class BNField6 {

	public static final String differentFields = "Operands are in different finite fields";

	/**
	 * BN parameters (singleton)
	 */
	BNParams bn;

	/**
	 * Components
	 */
	BNField2[] v;

	BNField6(BNParams bn) {
		this.bn = bn;
		v = new BNField2[3];
		this.v[0] = this.v[1] = this.v[2] = bn.Fp2_0;
	}

	BNField6(BNParams bn, BigInteger k) {
		this.bn = bn;
		v = new BNField2[3];
		this.v[0] = new BNField2(bn, k);
		this.v[1] = this.v[2] = bn.Fp2_0;
	}

	BNField6(BNParams bn, BNField2 v0) {
		this.bn = bn;
		v = new BNField2[3];
		this.v[0] = v0;
		this.v[1] = this.v[2] = bn.Fp2_0;
	}

	BNField6(BNParams bn, BNField2 v0, BNField2 v1, BNField2 v2) {
		this.bn = bn;
		v = new BNField2[3];
		this.v[0] = v0;
		this.v[1] = v1;
		this.v[2] = v2;
	}

	/**
	 * Compute a random field element.
	 *
	 * @param rand a cryptographically strong pseudo-random number generator.
	 *
	 * @return a random field element.
	 */
	BNField6(BNParams bn, SecureRandom rand) {
		this.bn = bn;
		v = new BNField2[3];
		this.v[0] = new BNField2(bn, rand);
		this.v[1] = new BNField2(bn, rand);
		this.v[2] = new BNField2(bn, rand);
	}

	public BNField6 randomize(SecureRandom rand) {
		return new BNField6(bn, rand);
	}

	public boolean isZero() {
		return v[0].isZero() && v[1].isZero() && v[2].isZero();
	}

	public boolean isOne() {
		return v[0].isOne() && v[1].isZero() && v[2].isZero();
	}

	public boolean equals(Object o) {
		if (!(o instanceof BNField6)) {
			return false;
		}
		BNField6 w = (BNField6) o;
		return bn == w.bn && // singleton comparison
				v[0].equals(w.v[0]) && v[1].equals(w.v[1]) && v[2].equals(w.v[2]);
	}

	public BNField6 negate() {
		return new BNField6(bn, v[0].negate(), v[1].negate(), v[2].negate());
	}

	/**
	 * Compute this^((p^2)^m), the m-th conjugate of this over GF(p^2).
	 */
	public BNField6 conjugate(int m) {
		switch (m) {
		default: // only to make the compiler happy
		case 0:
			return this;
		case 1:
			return new BNField6(bn, v[0], v[1].multiply(bn.zeta1).negate(), v[2].multiply(bn.zeta0));
		case 2:
			return new BNField6(bn, v[0], v[1].multiply(bn.zeta0), v[2].multiply(bn.zeta1).negate());
		}
	}

	public BNField6 add(BNField6 w) {
		if (bn != w.bn) { // singleton comparison
			throw new IllegalArgumentException(differentFields);
		}
		return new BNField6(bn, v[0].add(w.v[0]), v[1].add(w.v[1]), v[2].add(w.v[2]));
	}

	public BNField6 subtract(BNField6 w) {
		if (bn != w.bn) { // singleton comparison
			throw new IllegalArgumentException(differentFields);
		}
		return new BNField6(bn, v[0].subtract(w.v[0]), v[1].subtract(w.v[1]), v[2].subtract(w.v[2]));
	}

	public BNField6 twice(int k) {
		return new BNField6(bn, v[0].twice(k), v[1].twice(k), v[2].twice(k));
	}

	public BNField6 halve() {
		return new BNField6(bn, v[0].halve(), v[1].halve(), v[2].halve());
	}

	public BNField6 multiply(BNField6 w) {
		if (w == this) {
			return square();
		}
		if (bn != w.bn) { // singleton comparison
			throw new IllegalArgumentException(differentFields);
		}
		if (isOne() || w.isZero()) {
			return w;
		}
		if (isZero() || w.isOne()) {
			return this;
		}
		BNField2 d00 = v[0].multiply(w.v[0]), d11 = v[1].multiply(w.v[1]), d22 = v[2].multiply(w.v[2]),
				d01 = v[0].add(v[1]).multiply(w.v[0].add(w.v[1])).subtract(d00.add(d11)),
				d02 = v[0].add(v[2]).multiply(w.v[0].add(w.v[2])).subtract(d00.add(d22)),
				d12 = v[1].add(v[2]).multiply(w.v[1].add(w.v[2])).subtract(d11.add(d22));
		if (bn.b == 3) {
			return new BNField6(bn, d12.divideV().add(d00), d22.divideV().add(d01), d02.add(d11));
		} else {
			return new BNField6(bn, d12.multiplyV().add(d00), d22.multiplyV().add(d01), d02.add(d11));
		}
	}

	public BNField6 multiplyConj() {
		if (isOne() || isZero()) {
			return this;
		}
		if (bn.b == 3) {
			return new BNField6(bn, v[0].square().subtract(v[1].multiply(v[2]).divideV()),
					v[2].square().divideV().subtract(v[0].multiply(v[1])).multiply(bn.zeta0),
					v[0].multiply(v[2]).subtract(v[1].square()).multiply(bn.zeta1));
		} else {
			// (v0^2 - v1*v2*xi) + (v2^2*xi - v0*v1)*zeta*w + (v0*v2 - v1^2)*(zeta+1)*w^2 =
			return new BNField6(bn, v[0].square().subtract(v[1].multiply(v[2]).multiplyV()),
					v[2].square().multiplyV().subtract(v[0].multiply(v[1])).multiply(bn.zeta0),
					v[0].multiply(v[2]).subtract(v[1].square()).multiply(bn.zeta1));
		}
	}

	/**
	 * Complete the norm evaluation.
	 */
	public BNField2 normCompletion(BNField6 k) {
		BNField2 d00 = v[0].multiply(k.v[0]), d12 = v[1].multiply(k.v[2]).add(v[2].multiply(k.v[1]));
		if (bn.b == 3) {
			return d12.divideV().add(d00);
		} else {
			return d12.multiplyV().add(d00);
		}
	}

	public BNField6 multiply(BNField2 w) {
		if (bn != w.bn) { // singleton comparison
			throw new IllegalArgumentException(differentFields);
		}
		if (w.isOne()) {
			return this;
		}
		return new BNField6(bn, v[0].multiply(w), v[1].multiply(w), v[2].multiply(w));
	}

	public BNField6 square() {
		if (isZero() || isOne()) {
			return this;
		}
		BNField2 a0 = v[0];
		BNField2 a1 = v[1];
		BNField2 a2 = v[2];
		// Chung-Hasan SQR3 for F_{p^6} over F_{p^2}
		/*
		 * c0 = S0 = a0^2, S1 = (a2 + a1 + a0)^2, S2 = (a2 - a1 + a0)^2, c3 = S3 =
		 * 2*a1*a2, c4 = S4 = a2^2, T1 = (S1 + S2)/2, c1 = S1 - T1 - S3, c2 = T1 - S4 -
		 * S0.
		 */
		BNField2 c0 = a0.square();
		BNField2 S1 = a2.add(a1).add(a0).square();
		BNField2 S2 = a2.subtract(a1).add(a0).square();
		BNField2 c3 = a1.multiply(a2).twice(1);
		BNField2 c4 = a2.square();
		BNField2 T1 = S1.add(S2).halve();
		BNField2 c1 = S1.subtract(T1).subtract(c3);
		BNField2 c2 = T1.subtract(c4).subtract(c0);
		// z^3 = xi
		// z^4 = xi*z
		// c4^*xi*z + c3*xi + c2*z^2 + c1*z + c0
		// c2^*z^2 + (c4^*xi + c1)*z + (c3*xi + c0)
		if (bn.b == 3) {
			c0 = c0.add(c3.divideV());
			c1 = c1.add(c4.divideV());
		} else {
			c0 = c0.add(c3.multiplyV());
			c1 = c1.add(c4.multiplyV());
		}
		return new BNField6(bn, c0, c1, c2);
	}

	public BNField6 multiplyV() {
		// (a0, a1, a2) -> (a2*xi, a0, a1)
		return new BNField6(bn, v[2].multiplyV(), v[0], v[1]);
	}

	public BNField6 divideV() {
		// (a0, a1, a2) -> (a2/xi, a0, a1)
		return new BNField6(bn, v[2].divideV(), v[0], v[1]);
	}

	public String toString() {
		return "(" + v[0] + ", " + v[1] + ", " + v[2] + ")";
	}
}
