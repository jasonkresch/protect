/**
 * BNField12.java
 *
 * Arithmetic in the finite extension field GF(p^12) with p = 3 (mod 4).
 * This field is represented as GF(p^12) = GF(p^2)[z]/(z^6 - xi)
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

public class BNField12 {

	public static final String differentFields = "Operands are in different finite fields";

	/**
	 * BN parameters (singleton)
	 */
	BNParams bn;

	/**
	 * Components
	 */
	BNField2[] v;

	BNField12(BNParams bn, BigInteger k) {
		this.bn = bn;
		v = new BNField2[6];
		v[0] = new BNField2(bn, k); // caveat: no modular reduction!
		for (int i = 1; i < 6; i++) {
			v[i] = new BNField2(bn);
		}
	}

	BNField12(BNParams bn, BNField2[] v) {
		this.bn = bn;
		this.v = v;
	}

	/**
	 * Create a random field element.
	 *
	 * @param rand a cryptographically strong pseudo-random number generator.
	 *
	 * @return a random field element.
	 */
	BNField12(BNParams bn, SecureRandom rand) {
		this.bn = bn;
		v = new BNField2[6];
		for (int i = 0; i < 6; i++) {
			v[i] = new BNField2(bn, rand);
		}
	}

	/**
	 * Create a clone of a given field element.
	 *
	 * @param f the field element to be cloned.
	 */
	BNField12(BNField12 f) {
		this.bn = f.bn;
		v = new BNField2[6];
		for (int i = 0; i < 6; i++) {
			v[i] = f.v[i];
		}
	}

	/**
	 * Compute a random field element.
	 *
	 * @param rand a cryptographically strong pseudo-random number generator.
	 *
	 * @return a random field element.
	 */
	public BNField12 randomize(SecureRandom rand) {
		return new BNField12(bn, rand);
	}

	public boolean isZero() {
		return v[0].isZero() && v[1].isZero() && v[2].isZero() && v[3].isZero() && v[4].isZero() && v[5].isZero();
	}

	public boolean isOne() {
		return v[0].isOne() && v[1].isZero() && v[2].isZero() && v[3].isZero() && v[4].isZero() && v[5].isZero();
	}

	public boolean equals(Object o) {
		if (!(o instanceof BNField12)) {
			return false;
		}
		BNField12 w = (BNField12) o;
		return bn == w.bn && // singleton comparison
				v[0].equals(w.v[0]) && v[1].equals(w.v[1]) && v[2].equals(w.v[2]) && v[3].equals(w.v[3])
				&& v[4].equals(w.v[4]) && v[5].equals(w.v[5]);
	}

	public BNField12 negate() {
		BNField2[] w = new BNField2[6];
		for (int i = 0; i < 6; i++) {
			w[i] = v[i].negate();
		}
		return new BNField12(bn, w);
	}

	public BNField12 frobenius() {
		BNField2[] w = new BNField2[6];
		w[0] = v[0].conjugate();
		if (bn.b == 3) {
			w[1] = v[1].conjugate().multiplyV().multiply(bn.sigma);
			w[2] = v[2].conjugate().multiply(bn.zeta0).multiplyI().negate();
			w[3] = v[3].multiplyV().conjugate().multiply(bn.zeta0sigma);
			w[4] = v[4].conjugate().multiply(bn.zeta1);
			w[5] = v[5].conjugate().multiplyV().multiply(bn.zeta1sigma);
		} else {
			w[1] = v[1].multiplyV().conjugate().multiply(bn.zeta0sigma).negate();
			w[2] = v[2].conjugate().multiply(bn.zeta0).multiplyI();
			w[3] = v[3].conjugate().multiplyV().multiply(bn.zeta1sigma);
			w[4] = v[4].conjugate().multiply(bn.zeta1);
			w[5] = v[5].multiplyV().conjugate().multiply(bn.sigma);
		}
		return new BNField12(bn, w);
	}

	/**
	 * Compute this^((p^2)^m), the m-th conjugate of this over GF(p^2).
	 */
	public BNField12 conjugate(int m) {
		/*
		 * z^(p^2) = -zeta*z z^(p^4) = -(zeta+1)*z = zeta^2*z z^(p^6) = -z z^(p^8) =
		 * zeta*z z^(p^10) = (zeta+1)*z = -zeta^2*z
		 *
		 * v = v_0 + v_1 z + v_2 z^2 + v_3 z^3 + v_4 z^4 + v_5 z^5 => v^(p^2) = v_0 -
		 * v_1zeta z - v_2(zeta+1) z^2 - v_3 z^3 + v_4zeta z^4 + v_5(zeta+1) z^5 v^(p^4)
		 * = v_0 - v_1(zeta+1) z + v_2zeta z^2 + v_3 z^3 - v_4 z^4(zeta+1) + v_5zeta z^5
		 * v^(p^6) = v_0 - v_1 z + v_2 z^2 - v_3 z^3 + v_4 z^4 - v_5 z^5 v^(p^8) = v_0 +
		 * v_1zeta z - v_2(zeta+1) z^2 + v_3 z^3 + v_4zeta z^4 - v_5(zeta+1) z^5
		 * v^(p^10) = v_0 + v_1(zeta+1) z + v_2zeta z^2 - v_3 z^3 - v_4 z^4(zeta+1) -
		 * v_5zeta z^5
		 */
		BNField2[] w;
		switch (m) {
		default: // only to make the compiler happy
		case 0:
			return this;
		case 1:
			w = new BNField2[6];
			w[0] = v[0];
			w[1] = v[1].multiply(bn.zeta0).negate();
			w[2] = v[2].multiply(bn.zeta1).negate();
			w[3] = v[3].negate();
			w[4] = v[4].multiply(bn.zeta0);
			w[5] = v[5].multiply(bn.zeta1);
			return new BNField12(bn, w);
		case 2:
			w = new BNField2[6];
			w[0] = v[0];
			w[1] = v[1].multiply(bn.zeta1).negate();
			w[2] = v[2].multiply(bn.zeta0);
			w[3] = v[3];
			w[4] = v[4].multiply(bn.zeta1).negate();
			w[5] = v[5].multiply(bn.zeta0);
			return new BNField12(bn, w);
		case 3:
			w = new BNField2[6];
			w[0] = v[0];
			w[1] = v[1].negate();
			w[2] = v[2];
			w[3] = v[3].negate();
			w[4] = v[4];
			w[5] = v[5].negate();
			return new BNField12(bn, w);
		case 4:
			w = new BNField2[6];
			w[0] = v[0];
			w[1] = v[1].multiply(bn.zeta0);
			w[2] = v[2].multiply(bn.zeta1).negate();
			w[3] = v[3];
			w[4] = v[4].multiply(bn.zeta0);
			w[5] = v[5].multiply(bn.zeta1).negate();
			return new BNField12(bn, w);
		case 5:
			w = new BNField2[6];
			w[0] = v[0];
			w[1] = v[1].multiply(bn.zeta1);
			w[2] = v[2].multiply(bn.zeta0);
			w[3] = v[3].negate();
			w[4] = v[4].multiply(bn.zeta1).negate();
			w[5] = v[5].multiply(bn.zeta0).negate();
			return new BNField12(bn, w);
		}
	}

	public BNField12 add(BNField12 k) {
		if (bn != k.bn) { // singleton comparison
			throw new IllegalArgumentException(differentFields);
		}
		BNField2[] w = new BNField2[6];
		for (int i = 0; i < 6; i++) {
			w[i] = v[i].add(k.v[i]);
		}
		return new BNField12(bn, w);
	}

	public BNField12 subtract(BNField12 k) {
		if (bn != k.bn) { // singleton comparison
			throw new IllegalArgumentException(differentFields);
		}
		BNField2[] w = new BNField2[6];
		for (int i = 0; i < 6; i++) {
			w[i] = v[i].subtract(k.v[i]);
		}
		return new BNField12(bn, w);
	}

	public BNField12 multiply(BNField12 k) {
		if (k == this) {
			return square();
		}
		if (bn != k.bn) { // singleton comparison
			throw new IllegalArgumentException(differentFields);
		}
		if (isOne() || k.isZero()) {
			return k;
		}
		if (isZero() || k.isOne()) {
			return this;
		}

		BNField2.modoff();

		BNField2[] w = new BNField2[6];
		if (k.v[2].isZero() && k.v[4].isZero() && k.v[5].isZero()) {
			if (v[2].isZero() && v[4].isZero() && v[5].isZero()) {
				BNField2 d00 = v[0].multiply(k.v[0]), d11 = v[1].multiply(k.v[1]), d33 = v[3].multiply(k.v[3]),
						s01 = v[0].add(v[1]), t01 = k.v[0].add(k.v[1]), u01 = d00.add(d11), z01 = s01.multiply(t01),
						d01 = z01.subtract(u01),
						d13 = v[1].add(v[3]).multiply(k.v[1].add(k.v[3])).subtract(d11.add(d33));
				u01 = u01.add(d01);
				BNField2 d03 = s01.add(v[3]).multiply(t01.add(k.v[3])).subtract(u01.add(d33).add(d13)),
						d05 = z01.subtract(u01);
				if (bn.b == 3) {
					w[0] = d33.divideV().add(d00);
				} else {
					w[0] = d33.multiplyV().add(d00);
				}
				w[1] = d01;
				w[2] = d11;
				w[3] = d03;
				w[4] = d13;
				w[5] = d05;
			} else {
				BNField2 d00 = v[0].multiply(k.v[0]), d11 = v[1].multiply(k.v[1]), d33 = v[3].multiply(k.v[3]),
						s01 = v[0].add(v[1]), t01 = k.v[0].add(k.v[1]), u01 = d00.add(d11),
						d01 = s01.multiply(t01).subtract(u01), d02 = v[0].add(v[2]).multiply(k.v[0]).subtract(d00),
						d04 = v[0].add(v[4]).multiply(k.v[0]).subtract(d00),
						d13 = v[1].add(v[3]).multiply(k.v[1].add(k.v[3])).subtract(d11.add(d33)),
						d15 = v[1].add(v[5]).multiply(k.v[1]).subtract(d11), s23 = v[2].add(v[3]),
						d23 = s23.multiply(k.v[3]).subtract(d33), d35 = v[3].add(v[5]).multiply(k.v[3]).subtract(d33);
				u01 = u01.add(d01);
				BNField2 u23 = d33.add(d23),
						d03 = s01.add(s23).multiply(t01.add(k.v[3])).subtract(u01.add(u23).add(d02).add(d13)),
						s45 = v[4].add(v[5]), d05 = s01.add(s45).multiply(t01).subtract(u01.add(d04).add(d15)),
						d25 = s23.add(s45).multiply(k.v[3]).subtract(u23.add(d35));
				if (bn.b == 3) {
					w[0] = d15.add(d33).divideV().add(d00);
					w[1] = d25.divideV().add(d01);
					w[2] = d35.divideV().add(d02).add(d11);
				} else { // preferred representation:
					w[0] = d15.add(d33).multiplyV().add(d00);
					w[1] = d25.multiplyV().add(d01);
					w[2] = d35.multiplyV().add(d02).add(d11);
				}
				w[3] = d03;
				w[4] = d04.add(d13);
				w[5] = d05.add(d23);
			}
		} else if (k.v[1].isZero() && k.v[4].isZero() && k.v[5].isZero()) {
			BNField2 d00 = v[0].multiply(k.v[0]), d22 = v[2].multiply(k.v[2]), d33 = v[3].multiply(k.v[3]),
					s01 = v[0].add(v[1]), d01 = s01.multiply(k.v[0]).subtract(d00),
					d02 = v[0].add(v[2]).multiply(k.v[0].add(k.v[2])).subtract(d00.add(d22)),
					d04 = v[0].add(v[4]).multiply(k.v[0]).subtract(d00),
					d13 = v[1].add(v[3]).multiply(k.v[3]).subtract(d33), s23 = v[2].add(v[3]), t23 = k.v[2].add(k.v[3]),
					u23 = d22.add(d33), d23 = s23.multiply(t23).subtract(u23),
					d24 = v[2].add(v[4]).multiply(k.v[2]).subtract(d22),
					d35 = v[3].add(v[5]).multiply(k.v[3]).subtract(d33), u01 = d00.add(d01),
					d03 = s01.add(s23).multiply(k.v[0].add(t23)).subtract(u01.add(u23).add(d02).add(d13).add(d23)),
					s45 = v[4].add(v[5]), d05 = s01.add(s45).multiply(k.v[0]).subtract(u01.add(d04)),
					d25 = s23.add(s45).multiply(t23).subtract(u23.add(d23).add(d24).add(d35));
			if (bn.b == 3) {
				w[0] = d24.add(d33).divideV().add(d00);
				w[1] = d25.divideV().add(d01);
				w[2] = d35.divideV().add(d02);
			} else { // preferred representation:
				w[0] = d24.add(d33).multiplyV().add(d00);
				w[1] = d25.multiplyV().add(d01);
				w[2] = d35.multiplyV().add(d02);
			}
			w[3] = d03;
			w[4] = d04.add(d13).add(d22);
			w[5] = d05.add(d23);
		} else {
			BNField2 d00 = v[0].multiply(k.v[0]), d11 = v[1].multiply(k.v[1]), d22 = v[2].multiply(k.v[2]),
					d33 = v[3].multiply(k.v[3]), d44 = v[4].multiply(k.v[4]), d55 = v[5].multiply(k.v[5]),
					s01 = v[0].add(v[1]), t01 = k.v[0].add(k.v[1]), u01 = d00.add(d11),
					d01 = s01.multiply(t01).subtract(u01),
					d02 = v[0].add(v[2]).multiply(k.v[0].add(k.v[2])).subtract(d00.add(d22)),
					d04 = v[0].add(v[4]).multiply(k.v[0].add(k.v[4])).subtract(d00.add(d44)),
					d13 = v[1].add(v[3]).multiply(k.v[1].add(k.v[3])).subtract(d11.add(d33)),
					d15 = v[1].add(v[5]).multiply(k.v[1].add(k.v[5])).subtract(d11.add(d55)), s23 = v[2].add(v[3]),
					t23 = k.v[2].add(k.v[3]), u23 = d22.add(d33), d23 = s23.multiply(t23).subtract(u23),
					d24 = v[2].add(v[4]).multiply(k.v[2].add(k.v[4])).subtract(d22.add(d44)),
					d35 = v[3].add(v[5]).multiply(k.v[3].add(k.v[5])).subtract(d33.add(d55)), s45 = v[4].add(v[5]),
					t45 = k.v[4].add(k.v[5]), u45 = d44.add(d55), d45 = s45.multiply(t45).subtract(u45);
			u01 = u01.add(d01);
			u23 = u23.add(d23);
			u45 = u45.add(d45);
			BNField2 d03 = s01.add(s23).multiply(t01.add(t23)).subtract(u01.add(u23).add(d02).add(d13)),
					d05 = s01.add(s45).multiply(t01.add(t45)).subtract(u01.add(u45).add(d04).add(d15)),
					d25 = s23.add(s45).multiply(t23.add(t45)).subtract(u23.add(u45).add(d24).add(d35));
			if (bn.b == 3) {
				w[0] = d15.add(d24).add(d33).divideV().add(d00); // w[0] = c6/(1+i)+c0
				w[1] = d25.divideV().add(d01); // w[1] = c7/(1+i)+c1
				w[2] = d35.add(d44).divideV().add(d02).add(d11); // w[2] = c8/(1+i)+c2
				w[3] = d45.divideV().add(d03); // w[3] = c9/(1+i)+c3
				w[4] = d55.divideV().add(d04).add(d13).add(d22); // w[4] = c10/(1+i)+c4
				w[5] = d05.add(d23); // w[5] = c5
			} else { // preferred representation:
				w[0] = d15.add(d24).add(d33).multiplyV().add(d00);
				w[1] = d25.multiplyV().add(d01);
				w[2] = d35.add(d44).multiplyV().add(d02).add(d11);
				w[3] = d45.multiplyV().add(d03);
				w[4] = d55.multiplyV().add(d04).add(d13).add(d22);
				w[5] = d05.add(d23);
			}
		}

		BNField2.modon();
		BNField2.offsetmod(6);

		return new BNField12(bn, w);
	}

	public BNField12 multiply(BigInteger k) {
		BNField2[] w = new BNField2[6];
		for (int i = 0; i < 6; i++) {
			w[i] = v[i].multiply(k);
		}
		return new BNField12(bn, w);
	}

	public BNField12 multiply(BNField2 k) {
		BNField2[] w = new BNField2[6];
		for (int i = 0; i < 6; i++) {
			w[i] = v[i].multiply(k);
		}
		return new BNField12(bn, w);
	}

	public BNField12 multiply(BNField6 k) {
		BNField6 dr = new BNField6(bn, v[0], v[2], v[4]).multiply(k);
		BNField6 di = new BNField6(bn, v[1], v[3], v[5]).multiply(k);
		return new BNField12(bn, new BNField2[] { dr.v[0], di.v[0], dr.v[1], di.v[1], dr.v[2], di.v[2] });
	}

	public void decompress(BNField12 h) {
		// 3~s+3~m = 15 m
		if (!h.v[1].isZero()) {
			if (bn.b == 2) {
				h.v[3] = h.v[5].square().multiplyV().add(h.v[2].square().multiply(3)).subtract(h.v[4].twice(1))
						.multiply(h.v[1].twice(2).inverse());
				h.v[0] = h.v[3].square().twice(1).add(h.v[1].multiply(h.v[5]))
						.subtract(h.v[4].multiply(h.v[2]).multiply(3)).multiplyV().add(BigInteger.ONE);
			} else {
				h.v[3] = h.v[5].square().divideV().add(h.v[2].square().multiply(3)).subtract(h.v[4].twice(1))
						.multiply(h.v[1].twice(2).inverse());
				h.v[0] = h.v[3].square().twice(1).add(h.v[1].multiply(h.v[5]))
						.subtract(h.v[4].multiply(h.v[2]).multiply(3)).divideV().add(BigInteger.ONE);
			}
		} else {
			h.v[3] = h.v[2].multiply(h.v[5]).twice(1).multiply(h.v[4].inverse());
			h.v[0] = h.v[3].square().twice(1).subtract(h.v[4].multiply(h.v[2]).multiply(3)).multiplyV()
					.add(BigInteger.ONE);
		}
	}

	public BNField12 square() {
		if (isZero() || isOne()) {
			return this;
		}

		BNField2.modoff();

		/*
		 * BNField2.reset(); BNField2.counton(true); //
		 */

		// 4sF_p^4 + 1mF_p^4 = 4*(3sF_p^2)+3mF_p^2 = 30mF_p
		// Chung-Hasan SQR3
		BNField4 a0 = new BNField4(bn, v[0], v[3]);
		BNField4 a1 = new BNField4(bn, v[1], v[4]);
		BNField4 a2 = new BNField4(bn, v[2], v[5]);
		BNField4 c0 = a0.square();
		BNField4 S1 = a2.add(a1).add(a0).square();
		BNField4 S2 = a2.subtract(a1).add(a0).square();
		BNField4 c3 = a1.multiply(a2).twice(1);
		BNField4 c4 = a2.square();
		BNField4 T1 = S1.add(S2).halve();
		BNField4 c1 = S1.subtract(T1).subtract(c3);
		BNField4 c2 = T1.subtract(c4).subtract(c0);
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

		/*
		 * System.out.println("Chung-Hasan adds/subs: " + BNField2.getadd());
		 * System.out.println("Chung-Hasan muls: " + BNField2.getmul());
		 * System.out.println("Chung-Hasan squares: " + BNField2.getsqr());
		 * System.out.println("Chung-Hasan mods: " + BNField2.getmod()); System.exit(0);
		 * //
		 */

		BNField2.modon();
		BNField2.offsetmod(6);
		return new BNField12(bn, new BNField2[] { c0.re, c1.re, c2.re, c0.im, c1.im, c2.im });
	}

	public BNField12 compressedSquare() {
		// Karabina's technique to square a element of Cyclotomic Subgroup
		BNField12 h = new BNField12(bn.Fp12_0);
		BNField2 A23, A45, B23, B45;
		if (bn.b == 2) {
			A23 = v[1].add(v[4]).multiply(v[1].add(v[4].multiplyV()));
			A45 = v[2].add(v[5]).multiply(v[2].add(v[5].multiplyV()));
			B45 = v[2].multiply(v[5]);
			B23 = v[1].multiply(v[4]);

			h.v[1] = v[1].add(B45.multiplyV().multiply(3)).twice(1);
			h.v[4] = A45.subtract(B45.add(B45.multiplyV())).multiply(3).subtract(v[4].twice(1));
			h.v[2] = A23.subtract(B23.add(B23.multiplyV())).multiply(3).subtract(v[2].twice(1));
			h.v[5] = v[5].add(B23.multiply(3)).twice(1);
		} else {
			A23 = v[1].add(v[4]).multiply(v[1].add(v[4].divideV()));
			A45 = v[2].add(v[5]).multiply(v[2].add(v[5].divideV()));
			B45 = v[2].multiply(v[5]);
			B23 = v[1].multiply(v[4]);

			h.v[1] = v[1].add(B45.divideV().multiply(3)).twice(1);
			h.v[4] = A45.subtract(B45.add(B45.divideV())).multiply(3).subtract(v[4].twice(1));
			h.v[2] = A23.subtract(B23.add(B23.divideV())).multiply(3).subtract(v[2].twice(1));
			h.v[5] = v[5].add(B23.multiply(3)).twice(1);
		}

		// decompress(h);
		return h;
	}

	public BNField12 uniSquare() {

		BNField2.modoff();

		// * 18 mFp
		// Granger/Scott technique to square a element of Cyclotomic Subgroup
		BNField2 a0, a1, b0, b1, c0, c1, a0sqr, a1sqr, b0sqr, b1sqr, c0sqr, c1sqr;
		a0sqr = v[0].square();
		a1sqr = v[3].square();
		b0sqr = v[1].square();
		b1sqr = v[4].square();
		c0sqr = v[2].square();
		c1sqr = v[5].square();
		if (bn.b == 3) {
			// a0 = 3*(a0^2 + V^{-1}*a1^2) - 2*a0
			a0 = a1sqr.divideV().add(a0sqr).multiply(3).subtract(v[0].twice(1));
			// a1 = 3*[(a0+a1)^2 - a0^2 - a1^2] + 2*a1
			a1 = v[0].add(v[3]).square().subtract(a0sqr).subtract(a1sqr).multiply(3).add(v[3].twice(1));
			// b0 = 3V*[(c0 + c1)^2 - c_0^2 - c1^2] + 2*b0
			b0 = v[2].add(v[5]).square().subtract(c0sqr).subtract(c1sqr).multiply(3).divideV().add(v[1].twice(1));
			// b1 = 3*(c0^2 + V^{-1}*c1^2) - 2*b1
			b1 = c0sqr.add(c1sqr.divideV()).multiply(3).subtract(v[4].twice(1));
			// c0 = 3*(b0^2 + V^{-1}*b1^2) - 2*c0
			c0 = b1sqr.divideV().add(b0sqr).multiply(3).subtract(v[2].twice(1));
			// c1 = 3*[(b0 + b1)^2 - b0^2 - b1^2] + 2*c1
			c1 = v[1].add(v[4]).square().subtract(b0sqr).subtract(b1sqr).multiply(3).add(v[5].twice(1));
		} else {
			// A = 3a^2-2conj(a)
			// a0 = 3*(a0^2 + V*a1^2) - 2*a0
			a0 = a1sqr.multiplyV().add(a0sqr).multiply(3).subtract(v[0].twice(1));
			// a1 = 3*[(a0+a1)^2 - a0^2 - a1^2] + 2*a1
			a1 = v[0].add(v[3]).square().subtract(a0sqr).subtract(a1sqr).multiply(3).add(v[3].twice(1));
			// B = 3V*c^2-2conj(b)
			// b0 = 3V*[(c0 + c1)^2 - c_0^2 - c1^2] + 2*b0
			b0 = v[2].add(v[5]).square().subtract(c0sqr).subtract(c1sqr).multiply(3).multiplyV().add(v[1].twice(1));
			// b1 = 3*(c0^2 + V*c1^2) - 2*b1
			b1 = c0sqr.add(c1sqr.multiplyV()).multiply(3).subtract(v[4].twice(1));
			// C = 3b^2 - 2conj(c)
			// c0 = 3*(b0^2 + V*b1^2) - 2*c0
			c0 = b1sqr.multiplyV().add(b0sqr).multiply(3).subtract(v[2].twice(1));
			// c1 = 3*[(b0 + b1)^2 - b0^2 - b1^2] + 2*c1
			c1 = v[1].add(v[4]).square().subtract(b0sqr).subtract(b1sqr).multiply(3).add(v[5].twice(1));
		}

		BNField2.modon();
		BNField2.offsetmod(6);

		return new BNField12(bn, new BNField2[] { a0, b0, c0, a1, b1, c1 });
		// */
	}

	public BNField12 multiplyV() {
		// (a0, a1, a2, a3, a4, a5) -> (a4*xi, a5*xi, a0, a1, a2, a3)
		return new BNField12(bn, new BNField2[] { v[4].multiplyV(), v[5].multiplyV(), v[0], v[1], v[2], v[3] });
	}

	public BNField12 divideV() {
		// (a0, a1, a2, a3, a4, a5) -> (a4/xi, a5/xi, a0, a1, a2, a3)
		return new BNField12(bn, new BNField2[] { v[4].divideV(), v[5].divideV(), v[0], v[1], v[2], v[3] });
	}

	private BNField6 norm6() {
		// (a + bz)(a - bz) = a^2 - b^2*z^2 = a^2 - b^2*xi
		BNField6 re = new BNField6(bn, v[0], v[2], v[4]);
		BNField6 im = new BNField6(bn, v[1], v[3], v[5]);
		if (bn.b == 3) {
			return re.square().subtract(im.square().divideV());
		} else {
			return re.square().subtract(im.square().multiplyV());
		}
	}

	public BNField12 inverse() throws ArithmeticException {
		BNField2.modoff();

		// Total equiv: 22+15+9+9+36 = 91 mFp
		BNField6 l = norm6(); // l = f^{1+q^3} - 22 mFp
		BNField6 m = l.multiplyConj().conjugate(1); // m = (l^q)*(l^{q^2}) in F_q^3 - 15 mFp
		BNField2 e = l.normCompletion(m); // e = l*m - 9 mFp
		BNField6 d = m.multiply(e.inverse()); // d = m*e^{-1} - 9 mFp
		BNField12 c = conjugate(3).multiply(d); // c = d*f^{q^3} - 36 mFp

		BNField2.modon();
		BNField2.offsetmod(6);

		return c;
	}

	public BNField12 plainExp(BigInteger k) {
		/*
		 * This method is likely to be very fast, because k is very sparse
		 */
		BNField12 w = this;
		for (int i = k.bitLength() - 2; i >= 0; i--) {
			w = w.square();
			if (k.testBit(i)) {
				w = w.multiply(this);
			}
		}
		return w;
	}

	public BNField12 uniExp(BigInteger k) {
		BNField12 w = new BNField12(this);

		for (int i = k.bitLength() - 2; i >= 0; i--) {
			w = w.compressedSquare();// uniSquare();
			if (k.testBit(i)) {
				decompress(w);
				w = w.multiply(this);
			}
		}

		return w;
	}

	public BNField12 finExp() {
		BNField12 f = this;

		// p^12 - 1 = (p^6 - 1)*(p^2 + 1)*(p^4 - p^2 + 1)

		// BNField2.counton(true);
		// Compute the easy part
		f = f.conjugate(3).multiply(f.inverse()); // f = f^(p^6 - 1)
		f = f.conjugate(1).multiply(f); // f = f^(p^2 + 1)

		// BNField2.countoff(true);

		assert (f.inverse().equals(f.conjugate(3)));

		// *
		// Scott et al's technique to compute the hard part: f^{(p^{4}-p^{2}+1)/n}
		BNField12 fconj, fu, fu2, fu3, fp, fp2, fp3, fup, fu2p, fu3p, fu2p2;
		BNField12 y0, y1, y2, y3, y4, y5, y6, T0, T1;
		fconj = f.conjugate(3);
		if (bn.u.signum() >= 0) {
			fu = fconj.uniExp(bn.u); // fu = f^{p^6*u}
			fu2 = fu.conjugate(3).uniExp(bn.u); // fu2 = f^{p^12*u^2}
			fu3 = fu2.conjugate(3).uniExp(bn.u); // fu3 = f^{p^18*u^3}
		} else {
			fu = f.uniExp(bn.u.negate()); // fu = f^{-u}
			fu2 = fu.uniExp(bn.u.negate()); // fu2 = f^{u^2}
			fu3 = fu2.uniExp(bn.u.negate()); // fu3 = f^{-u^3}
		}

		fp = f.frobenius();
		fp2 = fp.frobenius();
		fp3 = fp2.frobenius();

		fup = fu.frobenius();
		fu2p = fu2.frobenius();
		fu3p = fu3.frobenius();
		fu2p2 = fu2.conjugate(1);

		y0 = fp.multiply(fp2).multiply(fp3);
		y1 = fconj;
		y2 = fu2p2;
		y3 = fup;
		y4 = fu.multiply(fu2p.conjugate(3));
		y5 = fu2.conjugate(3);
		y6 = fu3.multiply(fu3p);

		T0 = y6.uniSquare().multiply(y4).multiply(y5);
		T1 = y3.multiply(y5).multiply(T0).uniSquare();
		T0 = T0.multiply(y2);
		T1 = T1.multiply(T0).uniSquare();
		T0 = T1.multiply(y1).uniSquare();
		T1 = T1.multiply(y0);
		T0 = T0.multiply(T1);
		f = T0;

		return f;
	}

	public BNField12 exp(BigInteger k) {
		return plainExp(k);
	}

	public String toString() {
		return "(" + v[0] + ", " + v[1] + ", " + v[2] + ", " + v[3] + ", " + v[4] + ", " + v[5] + ")";
	}
}
