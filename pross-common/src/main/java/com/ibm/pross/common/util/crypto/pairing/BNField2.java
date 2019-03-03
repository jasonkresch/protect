/**
 * BNField2.java
 *
 * Arithmetic in the finite extension field GF(p^2) with p = 3 (mod 4) and p = 4 (mod 9).
 *
 * Copyright (C) Paulo S. L. M. Barreto, Pedro d'Aquino F. F. de Sa' Barbuda, and Geovandro C. C. F. Pereira.
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

public class BNField2 {

	public static final String differentFields = "Operands are in different finite fields";

	private static final int SMALLSIZE = 32;

	/**
	 * BN parameters (singleton)
	 */
	BNParams bn;

	/**
	 * "Real" part
	 */
	BigInteger re;

	/**
	 * "Imaginary" part
	 */
	BigInteger im;

	/*
	 * statistics
	 */
	static long addcount = 0;
	static long mulcount = 0;
	static long sqrcount = 0;
	static long modcount = 0;
	static long fpmcount = 0;
	static boolean docount = false;
	static boolean modenable = true;

	static void counton(boolean enable) {
		if (enable) {
			docount = true;
		}
	}

	static void countoff(boolean enable) {
		if (enable) {
			docount = false;
		}
	}

	static void modon() {
		modenable = true;
	}

	static void modoff() {
		modenable = false;
	}

	static void reset() {
		addcount = 0;
		mulcount = 0;
		sqrcount = 0;
		modcount = 0;
		fpmcount = 0;
	}

	static long getadd() {
		return addcount;
	}

	static long getmul() {
		return mulcount;
	}

	static long getsqr() {
		return sqrcount;
	}

	static long getmod() {
		return modcount / 2;
	}

	static long getfpm() {
		return fpmcount;
	}

	static void offsetmod(long delta) {
		if (docount) {
			modcount += delta;
		}
	}

	BNField2(BNParams bn) {
		this.bn = bn;
		this.re = BNParams._0;
		this.im = BNParams._0;
	}

	BNField2(BNParams bn, BigInteger re) {
		this.bn = bn;
		this.re = re; // caveat: no modular reduction!
		this.im = BNParams._0;
	}

	BNField2(BNParams bn, BigInteger re, BigInteger im, boolean reduce) {
		this.bn = bn;
		if (reduce) {
			if (docount && modenable) {
				if (re.signum() < 0 || re.compareTo(bn.p) >= 0) {
					modcount++;
				}
				if (im.signum() < 0 || im.compareTo(bn.p) >= 0) {
					modcount++;
				}
			}
			this.re = re.mod(bn.p);
			this.im = im.mod(bn.p);
		} else {
			this.re = re;
			this.im = im;
		}
	}

	BNField2(BNParams bn, SecureRandom rand) {
		this.bn = bn;
		do {
			re = new BigInteger(bn.p.bitLength(), rand);
		} while (re.compareTo(bn.p) >= 0);
		do {
			im = new BigInteger(bn.p.bitLength(), rand);
		} while (im.compareTo(bn.p) >= 0);
	}

	/**
	 * Compute a random field element.
	 *
	 * @param rand a cryptographically strong pseudo-random number generator.
	 *
	 * @return a random field element.
	 */
	public BNField2 randomize(SecureRandom rand) {
		return new BNField2(bn, rand);
	}

	public boolean isZero() {
		return re.signum() == 0 && im.signum() == 0;
	}

	public boolean isOne() {
		return re.compareTo(BNParams._1) == 0 && im.signum() == 0;
	}

	public boolean equals(Object u) {
		if (!(u instanceof BNField2)) {
			return false;
		}
		BNField2 v = (BNField2) u;
		return bn == v.bn && // singleton comparison
				re.compareTo(v.re) == 0 && im.compareTo(v.im) == 0;
	}

	/**
	 * -(x + yi)
	 */
	public BNField2 negate() {
		return new BNField2(bn, (re.signum() != 0) ? bn.p.subtract(re) : re,
				(im.signum() != 0) ? bn.p.subtract(im) : im, false);
	}

	/**
	 * (x + yi)^p = x - yi
	 */
	public BNField2 conjugate() {
		return new BNField2(bn, re, (im.signum() != 0) ? bn.p.subtract(im) : im, false);
	}

	/*
	 * public BigInteger norm() { return
	 * re.multiply(re).add(im.multiply(im)).mod(bn.p); } //
	 */

	public BNField2 add(BNField2 v) {
		if (bn != v.bn) { // singleton comparison
			throw new IllegalArgumentException(differentFields);
		}
		BigInteger r = re.add(v.re);
		if (docount && re.bitLength() > SMALLSIZE && v.re.bitLength() > SMALLSIZE) {
			addcount++;
		}
		if (r.compareTo(bn.p) >= 0) {
			r = r.subtract(bn.p);
		}
		BigInteger i = im.add(v.im);
		if (docount && im.bitLength() > SMALLSIZE && v.im.bitLength() > SMALLSIZE) {
			addcount++;
		}
		if (i.compareTo(bn.p) >= 0) {
			i = i.subtract(bn.p);
		}
		return new BNField2(bn, r, i, false);
	}

	public BNField2 add(BigInteger v) {
		BigInteger s = re.add(v);
		if (docount && re.bitLength() > SMALLSIZE && v.bitLength() > SMALLSIZE) {
			addcount++;
		}
		if (s.compareTo(bn.p) >= 0) {
			s = s.subtract(bn.p);
		}
		return new BNField2(bn, s, im, false);
	}

	public BNField2 subtract(BNField2 v) {
		if (bn != v.bn) { // singleton comparison
			throw new IllegalArgumentException(differentFields);
		}
		BigInteger r = re.subtract(v.re);
		if (docount && re.bitLength() > SMALLSIZE && v.re.bitLength() > SMALLSIZE) {
			addcount++;
		}
		if (r.signum() < 0) {
			r = r.add(bn.p);
		}
		BigInteger i = im.subtract(v.im);
		if (docount && im.bitLength() > SMALLSIZE && v.im.bitLength() > SMALLSIZE) {
			addcount++;
		}
		if (i.signum() < 0) {
			i = i.add(bn.p);
		}
		return new BNField2(bn, r, i, false);
	}

	public BNField2 subtract(BigInteger v) {
		if (docount && re.bitLength() > SMALLSIZE && v.bitLength() > SMALLSIZE) {
			addcount++;
		}
		BigInteger r = re.subtract(v);
		if (r.signum() < 0) {
			r = r.add(bn.p);
		}
		return new BNField2(bn, r, im, false);
	}

	public BNField2 twice(int k) {
		BigInteger r = re;
		BigInteger i = im;
		while (k-- > 0) {
			r = r.shiftLeft(1);
			if (r.compareTo(bn.p) >= 0) {
				r = r.subtract(bn.p);
			}
			i = i.shiftLeft(1);
			if (i.compareTo(bn.p) >= 0) {
				i = i.subtract(bn.p);
			}
		}
		return new BNField2(bn, r, i, false);
	}

	public BNField2 halve() {
		return new BNField2(bn, (re.testBit(0) ? re.add(bn.p) : re).shiftRight(1),
				(im.testBit(0) ? im.add(bn.p) : im).shiftRight(1), false);
	}

	/**
	 * (x + yi)(u + vi) = (xu - yv) + ((x + y)(u + v) - xu - yv)i
	 */
	public BNField2 multiply(BNField2 v) {
		if (this == v) {
			return square();
		}
		if (bn != v.bn) { // singleton comparison
			throw new IllegalArgumentException(differentFields);
		}
		if (isOne() || v.isZero()) {
			return v;
		}
		if (isZero() || v.isOne()) {
			return this;
		}
		// *
		if (docount) {
			addcount += 5;
			mulcount++;
			fpmcount += 3;
		}
		// */
		BigInteger re2 = re.multiply(v.re); // mod p
		BigInteger im2 = im.multiply(v.im); // mod p
		BigInteger mix = re.add(im).multiply(v.re.add(v.im)); // mod p;
		return new BNField2(bn, re2.subtract(im2), mix.subtract(re2).subtract(im2), true);
	}

	/**
	 * (x + yi)v = xv + yvi
	 */
	public BNField2 multiply(BigInteger v) {
		/*
		 * if (docount && v.bitLength() > SMALLSIZE) { fpmcount += 2; } //
		 */
		return new BNField2(bn, re.multiply(v), im.multiply(v), true);
	}

	/**
	 * s(x + yi) = sx + syi
	 */
	public BNField2 multiply(int s) {
		BigInteger newre = re.multiply(BigInteger.valueOf(s));
		while (newre.signum() < 0) {
			newre = newre.add(bn.p);
		}
		while (newre.compareTo(bn.p) >= 0) {
			newre = newre.subtract(bn.p);
		}
		BigInteger newim = im.multiply(BigInteger.valueOf(s));
		while (newim.signum() < 0) {
			newim = newim.add(bn.p);
		}
		while (newim.compareTo(bn.p) >= 0) {
			newim = newim.subtract(bn.p);
		}
		return new BNField2(bn, newre, newim, false);
	}

	/**
	 * (x + yi)^2 = (x + y)(x - y) + ((x+y)^2 - (x + y)(x - y))i
	 */
	public BNField2 square() {
		if (isZero() || isOne()) {
			return this;
		}
		if (im.signum() == 0) {
			// *
			if (docount) {
				fpmcount++;
			}
			// */
			return new BNField2(bn, re.multiply(re), BNParams._0, true);
		}
		if (re.signum() == 0) {
			// *
			if (docount) {
				fpmcount++;
			}
			// */
			return new BNField2(bn, im.multiply(im).negate(), BNParams._0, true);
		}
		// *
		if (docount) {
			addcount += 2;
			sqrcount++;
			fpmcount += 2;
		}
		// */
		return new BNField2(bn, re.add(im).multiply(re.subtract(im)), re.multiply(im).shiftLeft(1), true);
	}

	/**
	 * (x + yi)^3 = x(x^2 - 3y^2) + y(3x^2 - y^2)i
	 */
	public BNField2 cube() {
		/*
		 * if (docount) { addcount += 6; fpmcount += 4; } //
		 */
		BigInteger re2 = re.multiply(re); // mod p
		BigInteger im2 = im.multiply(im); // mod p
		return new BNField2(bn, re.multiply(re2.subtract(im2.add(im2).add(im2))),
				im.multiply(re2.add(re2).add(re2).subtract(im2)), true);
	}

	/**
	 * (x + yi)^{-1} = (x - yi)/(x^2 + y^2)
	 */
	public BNField2 inverse() throws ArithmeticException {
		/*
		 * if (docount) { addcount++; fpmcount += 4; } //
		 */
		BigInteger d = re.multiply(re).add(im.multiply(im)).modInverse(bn.p);
		return new BNField2(bn, re.multiply(d), bn.p.subtract(im).multiply(d), true);
	}

	/**
	 * (x + yi)i = (-y + xi)
	 */
	public BNField2 multiplyI() {
		return new BNField2(bn, (im.signum() != 0) ? bn.p.subtract(im) : im, re, false);
	}

	/**
	 * (x + yi)/i = y - xi
	 */
	public BNField2 divideI() {
		return new BNField2(bn, im, (re.signum() != 0) ? bn.p.subtract(re) : re, false);
	}

	/**
	 * (x + yi)(1 + i) = (x - y) + (x + y)i
	 */
	public BNField2 multiplyV() {
		/*
		 * if (docount) { addcount += 2; } //
		 */
		BigInteger r = re.subtract(im);
		if (r.signum() < 0) {
			r = r.add(bn.p);
		}
		BigInteger i = re.add(im);
		if (i.compareTo(bn.p) >= 0) {
			i = i.subtract(bn.p);
		}
		return new BNField2(bn, r, i, false);
	}

	public BNField2 divideV() {
		/*
		 * if (docount) { addcount += 2; } //
		 */
		BigInteger qre = re.add(im);
		if (qre.compareTo(bn.p) >= 0) {
			qre = qre.subtract(bn.p);
		}
		BigInteger qim = im.subtract(re);
		if (qim.signum() < 0) {
			qim = qim.add(bn.p);
		}
		return new BNField2(bn, (qre.testBit(0) ? qre.add(bn.p) : qre).shiftRight(1),
				(qim.testBit(0) ? qim.add(bn.p) : qim).shiftRight(1), false);
	}

	public BNField2 exp(BigInteger k) {
		BNField2 P = this;
		if (k.signum() < 0) {
			k = k.negate();
			P = P.inverse();
		}
		byte[] e = k.toByteArray();
		BNField2[] mP = new BNField2[16];
		mP[0] = bn.Fp2_1;
		mP[1] = P;
		for (int m = 1; m <= 7; m++) {
			mP[2 * m] = mP[m].square();
			mP[2 * m + 1] = mP[2 * m].multiply(P);
		}
		BNField2 A = mP[0];
		for (int i = 0; i < e.length; i++) {
			int u = e[i] & 0xff;
			A = A.square().square().square().square().multiply(mP[u >>> 4]).square().square().square().square()
					.multiply(mP[u & 0xf]);
		}
		return A;
	}

	/**
	 * Compute a square root of this.
	 *
	 * @return a square root of this if one exists, or null otherwise.
	 */
	public BNField2 sqrt() {
		if (this.isZero()) {
			return this;
		}
		BNField2 r = this.exp(bn.sqrtExponent2); // r = v^{(p^2 + 7)/16}
		BNField2 r2 = r.square();
		if (r2.subtract(this).isZero()) {
			return r;
		}
		if (r2.add(this).isZero()) {
			return r.multiplyI();
		}
		r2 = r2.multiplyI();
		// BNField2 sqrtI = new BNField2(bn, bn.invSqrtMinus2,
		// bn.p.subtract(bn.invSqrtMinus2), false); // sqrt(i) = (1 - i)/sqrt(-2)
		r = r.multiply(bn.sqrtI);
		if (r2.subtract(this).isZero()) {
			return r;
		}
		if (r2.add(this).isZero()) {
			return r.multiplyI();
		}
		return null;
	}

	/**
	 * Compute a cube root of this.
	 *
	 * @return a cube root of this if one exists, or null otherwise.
	 */
	public BNField2 cbrt() {
		assert (bn.p.mod(BNParams._9).intValue() == 4);
		if (this.isZero()) {
			return this;
		}
		BNField2 r = this.exp(bn.cbrtExponent2); // r = v^{(p^2 + 2)/9}
		return r.cube().subtract(this).isZero() ? r : null;
	}

	public String toString() {
		return "(" + re + ", " + im + ")";
	}
}
