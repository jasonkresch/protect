/**
 * BNField4.java
 *
 * Arithmetic in the finite extension field GF(p^4) with p = 3 (mod 4).
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

public class BNField4 {

	public static final String differentFields = "Operands are in different finite fields";

	/**
	 * BN parameters (singleton)
	 */
	BNParams bn;

	/**
	 * "Real" part
	 */
	BNField2 re;

	/**
	 * "Imaginary" part
	 */
	BNField2 im;

	BNField4(BNParams bn) {
		this.bn = bn;
		this.re = this.im = bn.Fp2_0;
	}

	BNField4(BNParams bn, BigInteger k) {
		this.bn = bn;
		this.re = new BNField2(bn, k);
		this.im = bn.Fp2_0;
	}

	BNField4(BNParams bn, BNField2 re) {
		this.bn = bn;
		this.re = re;
		this.im = bn.Fp2_0;
	}

	BNField4(BNParams bn, BNField2 re, BNField2 im) {
		this.bn = bn;
		this.re = re;
		this.im = im;
	}

	/**
	 * Compute a random field element.
	 *
	 * @param rand a cryptographically strong pseudo-random number generator.
	 *
	 * @return a random field element.
	 */
	BNField4(BNParams bn, SecureRandom rand) {
		this.bn = bn;
		this.re = new BNField2(bn, rand);
		this.im = new BNField2(bn, rand);
	}

	public BNField4 randomize(SecureRandom rand) {
		return new BNField4(bn, rand);
	}

	public boolean isZero() {
		return re.isZero() && im.isZero();
	}

	public boolean isOne() {
		return re.isOne() && im.isZero();
	}

	public boolean equals(Object o) {
		if (!(o instanceof BNField4)) {
			return false;
		}
		BNField4 w = (BNField4) o;
		return bn == w.bn && // singleton comparison
				re.equals(w.re) && im.equals(w.im);
	}

	public BNField4 negate() {
		return new BNField4(bn, re.negate(), im.negate());
	}

	public BNField4 add(BNField4 w) {
		if (bn != w.bn) { // singleton comparison
			throw new IllegalArgumentException(differentFields);
		}
		return new BNField4(bn, re.add(w.re), im.add(w.im));
	}

	public BNField4 subtract(BNField4 w) {
		if (bn != w.bn) { // singleton comparison
			throw new IllegalArgumentException(differentFields);
		}
		return new BNField4(bn, re.subtract(w.re), im.subtract(w.im));
	}

	public BNField4 twice(int k) {
		return new BNField4(bn, re.twice(k), im.twice(k));
	}

	public BNField4 halve() {
		return new BNField4(bn, re.halve(), im.halve());
	}

	// (re + im*v)*v = im*xi + re*v
	public BNField4 multiplyV() {
		return new BNField4(bn, im.multiplyV(), re);
	}

	public BNField4 divideV() {
		return new BNField4(bn, im.divideV(), re);
	}

	public BNField4 multiply(BNField4 w) {
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
		BNField2 b0 = re;
		BNField2 b1 = im;
		BNField2 c0 = w.re;
		BNField2 c1 = w.im;
		// [b0, b1]*[c0, c1] = [b0*c0 + b1*c1*xi, (b0 + b1)*(c0 + c1) - b0*c0 - b1*c1]
		BNField2 b0c0 = b0.multiply(c0);
		BNField2 b1c1 = b1.multiply(c1);
		return new BNField4(bn, (bn.b == 3) ? b0c0.add(b1c1.divideV()) : b0c0.add(b1c1.multiplyV()),
				b0.add(b1).multiply(c0.add(c1)).subtract(b0c0).subtract(b1c1));
	}

	public BNField4 multiply(BNField2 w) {
		if (bn != w.bn) { // singleton comparison
			throw new IllegalArgumentException(differentFields);
		}
		if (w.isOne()) {
			return this;
		}
		return new BNField4(bn, re.multiply(w), im.multiply(w));
	}

	public BNField4 square() {
		if (isZero() || isOne()) {
			return this;
		}
		BNField2 a0 = re;
		BNField2 a1 = im;
		// [a0, a1]^2 = [a0^2 + a1^2*xi, (a0 + a1)^2 - a0^2 - a1^2]
		BNField2 a02 = a0.square();
		BNField2 a12 = a1.square();
		return new BNField4(bn, (bn.b == 3) ? a02.add(a12.divideV()) : a02.add(a12.multiplyV()),
				a0.add(a1).square().subtract(a02).subtract(a12));
	}

	/**
	 * (x + ys)^{-1} = (x - ys)/(x^2 - y^2*xi)
	 */
	public BNField4 inverse() throws ArithmeticException {
		BNField2 d = re.square().subtract(im.square().multiplyV());
		return new BNField4(bn, re.multiply(d), im.multiply(d).negate());
	}

	public String toString() {
		return "(" + re + ", " + im + ")";
	}
}
