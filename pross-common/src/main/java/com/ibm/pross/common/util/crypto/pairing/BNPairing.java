/**
 * BNPairing.java
 *
 * Bilinear pairings over Barreto-Naehrig (BN) elliptic curves.
 *
 * Copyright (C) Paulo S. L. M. Barreto, Michael Naehrig, Peter Schwabe, and Geovandro C. C. F. Pereira.
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

public class BNPairing {

	/**
	 * Convenient BigInteger constants
	 */
	private static final BigInteger _1 = BigInteger.valueOf(1L);

	public static final String incompatibleCurves = "Cannot compute pairings of points from incompatible elliptic curves";

	public BNCurve E;
	public BNCurve2 E2;
	public BNParams bn;

	public BNField12 Fp12_0, Fp12_1;

	static long addcount = 0;
	static long mulcount = 0;
	static long sqrcount = 0;
	static long modcount = 0;
	static long fpmcount = 0;

	static void reset() {
		addcount = 0;
		mulcount = 0;
		sqrcount = 0;
		modcount = 0;
		fpmcount = 0;
		BNField2.reset();
	}

	static void update() {
		addcount += BNField2.getadd();
		mulcount += BNField2.getmul();
		sqrcount += BNField2.getsqr();
		modcount += BNField2.getmod();
		fpmcount += BNField2.getfpm();
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
		return modcount;
	}

	static long getfpm() {
		return fpmcount;
	}

	/**
	 * Powers of the base element g by simple multiples of powers of 16.
	 */
	protected BNField12[][] gp16 = null;

	public BNPairing(BNCurve2 Et) {
		E2 = Et;
		E = Et.E;
		bn = E.bn;
		Fp12_0 = bn.Fp12_0;
		Fp12_1 = bn.Fp12_1;
		gp16 = new BNField12[(bn.n.bitLength() + 3) / 4][16];
	}

	// *
	BNField12 gl(BNPoint V, BNPoint P, BNPoint2 Q) {
		BigInteger n, d;
		BigInteger p = bn.p;
		if (V.isZero() || P.isZero() || Q.isZero()) {
			return Fp12_1;
		}
		assert (!V.opposite(P));
		BigInteger Vz3 = V.z.multiply(V.z).multiply(V.z).mod(p);
		if (V.equals(P)) {
			// y = Y/Z^3 => 1/2y = Z^3/2Y
			// x = X/Z^2 => 3x^2 = 3X^2/Z^4 =>
			// => lambda = 3x^2/2y = 3X^2/(2Y*Z)
			n = V.x.multiply(V.x).multiply(BigInteger.valueOf(3L));// .mod(p);
			d = V.y.multiply(V.z).shiftLeft(1);// .mod(p);
		} else {
			// lambda = (P.y - V.y)/(P.x - V.x) // P.Z = 1
			// = (P.Y - V.Y/V.Z^3) / (P.X - V.X/V.Z^2)
			// = (P.Y*V.Z^3 - V.Y) / (P.X*V.Z^3 - V.X*V.Z)
			assert (P.z.compareTo(_1) == 0);
			n = P.y.multiply(Vz3).subtract(V.y);// .mod(p);
			d = P.x.multiply(Vz3).subtract(V.x.multiply(V.z));// .mod(p);
		}
		// lambda = n/d
		BNField2[] w = new BNField2[6];
		// n*(Qt[1]*z^2 - V.x) + d*(V.y - Qt[2]*z^3);
		// n*Q.x*z^2 - n*V.x + d*V.y - d*Q.y*z^3;
		// (d*V.y - n*V.x) + n*Q.x*z^2 - d*Q.y*z^3;
		// (d*V.Y/V.Z^3 - n*V.X/V.Z^2) + n*Q.x*z^2 - d*Q.y*z^3;
		// (d*V.Y - n*V.X*V.Z) + n*Q.x*V.Z^3*z^2 - d*Q.y*V.Z^3*z^3;
		w[0] = new BNField2(bn, d.multiply(V.y).subtract(n.multiply(V.x).multiply(V.z)).mod(bn.p));
		w[2] = Q.x.multiply(n.multiply(Vz3));
		w[3] = Q.y.multiply(p.subtract(d).multiply(Vz3));
		w[1] = w[4] = w[5] = E2.Fp2_0;
		return new BNField12(bn, w);
	}

	public BNField12 tate(BNPoint P, BNPoint2 Q) {
		assert (E.contains(P) && E2.contains(Q));
		BNField12 f = Fp12_1;
		P = P.normalize();
		Q = Q.normalize();
		if (!P.isZero() && !Q.isZero()) {
			BNParams bn = E.bn;
			BNPoint V = P;
			for (int i = bn.n.bitLength() - 2; i >= 0; i--) {
				f = f.square().multiply(gl(V, V, Q));
				V = V.twice(1);
				if (bn.n.testBit(i)) {
					f = f.multiply(gl(V, P, Q));
					V = V.add(P);
				}
			}
			f = f.finExp();
		}
		return f;
	}

	// The eta (sometimes called twisted ate) pairing for points P and Q on BN
	// curves E and E'.
	public BNField12 eta(BNPoint P, BNPoint2 Q) {
		assert (E.contains(P) && E2.contains(Q));
		BNField12 f = Fp12_1;
		P = P.normalize();
		Q = Q.normalize();
		if (!P.isZero() && !Q.isZero()) {
			BNParams bn = E.bn;
			BNPoint V = P;
			BigInteger ord = bn.rho; // the Tate pairing would have order bn.n instead of bn.rho
			for (int i = ord.bitLength() - 2; i >= 0; i--) {
				f = f.square().multiply(gl(V, V, Q));
				V = V.twice(1);
				if (ord.testBit(i)) {
					f = f.multiply(gl(V, P, Q));
					V = V.add(P);
				}
			}
			if (bn.u.signum() < 0) {
				// Aranha's trick:
				f = f.conjugate(3);
				// f = f.inverse(); // f = f_{6u+2,Q}
			}
			f = f.finExp();
		}
		return f;
	}
	// */

	/*
	 * BNField12 gl(BNPoint2 T, BNPoint2 Q, BNPoint P) { BNField2 n, d; if
	 * (T.isZero() || P.isZero() || Q.isZero()) { return Fp12_1; } assert
	 * (!T.opposite(Q)); BNField2 Tz3 = T.z.cube(); if (T.equals(Q)) { // y = Y/Z^3
	 * => 1/2y = Z^3/2Y // x = X/Z^2 => 3x^2 = 3X^2/Z^4 => // => lambda = 3x^2/2y =
	 * 3X^2/(2Y*Z) n = T.x.square().multiply(BigInteger.valueOf(3L)); d =
	 * T.y.multiply(T.z).twice(1); } else { // lambda = (Q.y - T.y)/(Q.x - T.x) //
	 * Q.Z = 1 // = (Q.Y - T.Y/T.Z^3) / (Q.X - T.X/T.Z^2) // = (Q.Y*T.Z^3 - T.Y) /
	 * (Q.X*T.Z^3 - T.X*T.Z) assert (Q.z.isOne()); n =
	 * Q.y.multiply(Tz3).subtract(T.y); d =
	 * Q.x.multiply(Tz3).subtract(T.x.multiply(T.z)); } // lambda = n/d BNField2[] w
	 * = new BNField2[6]; //n*(P.x - T.x*z^2)*z + d*(T.y*z^3 - P.y); //-d*P.y +
	 * n*P.x*z + (d*T.y - n*T.x)*z^3; //-d*P.y + n*P.x*z + (d*T.Y/T.Z^3 -
	 * n*T.X/T.Z^2)*z^3; //-d*P.y*T.Z^3 + n*P.x*T.Z^3*z + (d*T.Y - n*T.X*T.Z)*z^3;
	 * w[0] = d.multiply(bn.p.subtract(P.y)).multiply(Tz3); w[1] =
	 * n.multiply(P.x).multiply(Tz3); w[3] =
	 * d.multiply(T.y).subtract(n.multiply(T.x).multiply(T.z)); w[2] = w[4] = w[5] =
	 * E2.Fp2_0; return new BNField12(bn, w); } //
	 */

	/*
	 * // Naive implementation of the ate pairing public BNField12 ate(BNPoint2 Q,
	 * BNPoint P) { assert (E2.contains(Q) && E.contains(P)); BNField12 f = Fp12_1;
	 * P = P.normalize(); Q = Q.normalize(); if (!P.isZero() && !Q.isZero()) {
	 * BNParams bn = E.bn; BNPoint2 T = Q; BigInteger ord = bn.t.subtract(_1); for
	 * (int i = ord.bitLength() - 2; i >= 0; i--) { f = f.square().multiply(gl(T, T,
	 * P)); T = T.twice(1); if (ord.testBit(i)) { f = f.multiply(gl(T, Q, P)); T =
	 * T.add(Q); } } f = f.finExp(); } return f; } //
	 */

	// *
	// improved implementation of the ate pairing
	public BNField12 ate(BNPoint2 Q, BNPoint P) {
		assert (E2.contains(Q) && E.contains(P));
		BNField12 f = Fp12_1;
		P = P.normalize();
		Q = Q.normalize();
		if (!P.isZero() && !Q.isZero()) {
			BigInteger ord = bn.t.subtract(BNParams._1);

			BNField2 X = Q.x;
			BNField2 Y = Q.y;
			BNField2 Z = Q.z;
			BNField2 A, B, C, D, E, F, G;
			BNField2[] w = new BNField2[6];// , w1 = new BNField2[6], w2 = new BNField2[6];
			BNField12 line;
			int start = ord.bitLength() - 2;
			for (int i = start; i >= 0; i--) {
				// Costello et al's double-and-line technique
				A = X.square();
				B = Y.square();
				C = Z.square();
				if (bn.b == 3) {
					D = C.multiply(3 * bn.b).multiplyV();
				} else {
					D = C.multiply(3 * bn.b).divideV();
				}
				F = Y.add(Z).square().subtract(B).subtract(C);
				if (i > 0) {
					E = X.add(Y).square().subtract(A).subtract(B);
					G = D.multiply(3);
					X = E.multiply(B.subtract(G));
					Y = B.add(G).square().subtract(D.square().twice(2).multiply(3));
					Z = B.multiply(F).twice(2);
				}
				// line = L_10*x_P + L_01*y_P*z + L_00*z^3
				w[0] = F.multiply(P.y.negate()); // L_{0,1}
				w[1] = A.multiply(3).multiply(P.x); // L_{1,0}
				w[3] = D.subtract(B); // L_{0,0}
				w[2] = w[4] = w[5] = E2.Fp2_0;
				line = new BNField12(bn, w);
				if (i != ord.bitLength() - 2) {
					f = f.square().multiply(line);
				} else {
					f = new BNField12(line);
				}
				if (ord.testBit(i)) {
					// Costello et al's add-and-line technique
					A = X.subtract(Z.multiply(Q.x));
					B = Y.subtract(Z.multiply(Q.y));
					// gADD = B*Q.x - A*Q.y - B*P.x + A*P.y;
					w[0] = A.multiply(P.y); // L_{0,1}
					w[1] = B.multiply(P.x.negate()); // L_{1,0}
					w[3] = B.multiply(Q.x).subtract(A.multiply(Q.y)); // L_{0,0}
					w[2] = w[4] = w[5] = E2.Fp2_0;
					line = new BNField12(bn, w);
					f = f.multiply(line);
					C = A.square();
					X = X.multiply(C);
					C = C.multiply(A);
					D = B.square().multiply(Z).add(C).subtract(X.twice(1));
					Y = B.multiply(X.subtract(D)).subtract(Y.multiply(C));
					X = A.multiply(D);
					Z = Z.multiply(C);
				}
			}

			f = f.finExp();
		}
		return f;
	}
	// */

	/*
	 * // naive implementation of the optimal pairing public BNField12 opt(BNPoint2
	 * Q, BNPoint P) { assert (E2.contains(Q) && E.contains(P)); BNField12 f =
	 * Fp12_1; P = P.normalize(); Q = Q.normalize(); if (!P.isZero() && !Q.isZero())
	 * { BNParams bn = E.bn; BNPoint2 T = Q; BigInteger ord = bn.optOrd; // 6u+2 for
	 * (int i = ord.bitLength() - 2; i >= 0; i--) { f = f.square().multiply(gl(T, T,
	 * P)); T = T.twice(1); if (ord.testBit(i)) { f = f.multiply(gl(T, Q, P)); T =
	 * T.add(Q); } } // now T = [|6u+2|]Q and f = f_{|6u+2|,Q} if (bn.u.signum() <
	 * 0) { // Aranha's trick: f = f.conjugate(3); //f = f.inverse(); // f =
	 * f_{6u+2,Q} } // optimal pairing: f =
	 * f_{6u+2,Q}(P)*l_{Q3,-Q2}(P)*l_{-Q2+Q3,Q1}(P)*l_{Q1-Q2+Q3,[6u+2]Q}(P) BNPoint2
	 * Q1 = Q.frobex(1); BNPoint2 Q2 = Q.frobex(2).negate(); BNPoint2 Q3 =
	 * Q.frobex(3); BNPoint2 Q4 = Q2.add(Q3); f = f.multiply(gl(Q2, Q3,
	 * P)).multiply(gl(Q4, Q1, P)); f = f.finExp(); } return f; } //
	 */

	static public boolean MillerLoop = true;
	static public boolean FinalExp = true;

	// *
	// improved implementation of the optimal pairing
	public BNField12 opt(BNPoint2 Q, BNPoint P) {
		assert (E2.contains(Q) && E.contains(P));
		BNField12 f = Fp12_1;
		P = P.normalize();
		Q = Q.normalize();
		reset();
		BNField2.countoff(true);
		if (!P.isZero() && !Q.isZero()) {
			BigInteger ord = bn.optOrd; // |6u+2|
			BNField2.counton(MillerLoop);

			BNField2 X = Q.x;
			BNField2 Y = Q.y;
			BNField2 Z = Q.z;
			BNField2 A, B, C, D, E, F, G;
			BNField2[] w = new BNField2[6];// , w1 = new BNField2[6], w2 = new BNField2[6];
			BNField12 line, line1, line2;
			int start = ord.bitLength() - 2;
			for (int i = start; i >= 0; i--) {
				// Costello et al's double-and-line technique
				A = X.square();
				B = Y.square();
				C = Z.square();
				if (bn.b == 3) {
					D = C.multiply(3 * bn.b).multiplyV();
				} else {
					D = C.multiply(3 * bn.b).divideV();
				}
				F = Y.add(Z).square().subtract(B).subtract(C);
				if (i > 0) {
					E = X.add(Y).square().subtract(A).subtract(B);
					G = D.multiply(3);
					X = E.multiply(B.subtract(G));
					Y = B.add(G).square().subtract(D.square().twice(2).multiply(3));
					Z = B.multiply(F).twice(2);
				}
				// line = L_10*x_P + L_01*y_P*z + L_00*z^3
				w[0] = F.multiply(P.y.negate()); // L_{0,1}
				w[1] = A.multiply(3).multiply(P.x); // L_{1,0}
				w[3] = D.subtract(B); // L_{0,0}
				w[2] = w[4] = w[5] = E2.Fp2_0;
				line = new BNField12(bn, w);
				if (i != ord.bitLength() - 2) {
					f = f.square().multiply(line);
				} else {
					f = new BNField12(line);
				}
				if (ord.testBit(i)) {
					// Costello et al's add-and-line technique
					A = X.subtract(Z.multiply(Q.x));
					B = Y.subtract(Z.multiply(Q.y));
					// gADD = B*Q.x - A*Q.y - B*P.x + A*P.y;
					w[0] = A.multiply(P.y); // L_{0,1}
					w[1] = B.multiply(P.x.negate()); // L_{1,0}
					w[3] = B.multiply(Q.x).subtract(A.multiply(Q.y)); // L_{0,0}
					w[2] = w[4] = w[5] = E2.Fp2_0;
					line = new BNField12(bn, w);
					f = f.multiply(line);
					C = A.square();
					X = X.multiply(C);
					C = C.multiply(A);
					D = B.square().multiply(Z).add(C).subtract(X.twice(1));
					Y = B.multiply(X.subtract(D)).subtract(Y.multiply(C));
					X = A.multiply(D);
					Z = Z.multiply(C);
					// BNField2.countoff(MillerLoop);

				}
			}

			// now T = [|6u+2|]Q and f = f_{|6u+2|,Q}
			if (bn.u.signum() < 0) {
				// Aranha's trick:
				f = f.conjugate(3);
				// f = f.inverse(); // f = f_{6u+2,Q}
			}
			// optimal pairing: f =
			// f_{6u+2,Q}(P)*l_{Q3,-Q2}(P)*l_{-Q2+Q3,Q1}(P)*l_{Q1-Q2+Q3,[6u+2]Q}(P)

			BNPoint2 Q1 = Q.frobex(1);
			BNPoint2 Q2 = Q.frobex(2).negate();
			BNPoint2 Q3 = Q.frobex(3);

			// Costello et al's add-and-line technique
			X = Q2.x;
			Y = Q2.y;
			Z = Q2.z;
			A = X.subtract(Q3.x);
			B = Y.subtract(Q3.y);
			// A = X.subtract(Z.multiply(Q3.x)); B = Y.subtract(Z.multiply(Q3.y));
			// gADD = B*Q3.x - A*Q3.y - B*P.x + A*P.y;
			w[0] = A.multiply(P.y); // L_{0,1}
			w[1] = B.multiply(P.x.negate()); // L_{1,0}
			w[3] = B.multiply(Q3.x).subtract(A.multiply(Q3.y)); // L_{0,0}
			w[2] = w[4] = w[5] = E2.Fp2_0;
			line = new BNField12(bn, w);
			line1 = new BNField12(line);

			C = A.square();
			X = X.multiply(C);
			C = C.multiply(A);
			D = B.square().add(C).subtract(X.twice(1));
			Y = B.multiply(X.subtract(D)).subtract(Y.multiply(C));
			X = A.multiply(D);
			Z = C;

			// Costello et al's add-and-line technique
			// X = Q4.x; Y = Q4.y; Z = Q4.z;
			A = X.subtract(Z.multiply(Q1.x));
			B = Y.subtract(Z.multiply(Q1.y));
			// gADD = B*Q1.x - A*Q1.y - B*P.x + A*P.y;
			w[0] = A.multiply(P.y); // L_{0,1}
			w[1] = B.multiply(P.x.negate()); // L_{1,0}
			w[3] = B.multiply(Q1.x).subtract(A.multiply(Q1.y)); // L_{0,0}
			w[2] = w[4] = w[5] = E2.Fp2_0;
			line = new BNField12(bn, w);
			line2 = new BNField12(line);
			f = f.multiply(line1.multiply(line2));

			BNField2.countoff(MillerLoop);

			BNField2.counton(FinalExp);
			f = f.finExp();
			BNField2.countoff(FinalExp);
		}
		update();
		return f;
	}
	// */

	protected BNField12 g = null;

	public void gSet(BNField12 g) {
		this.g = g;
		BNField12[] gp16i = gp16[0];
		gp16i[0] = Fp12_1;
		gp16i[1] = g;
		for (int i = 1, j = 2; i <= 7; i++, j += 2) {
			gp16i[j] = gp16i[i].square();
			gp16i[j + 1] = gp16i[j].multiply(g);
		}
		for (int i = 1; i < gp16.length; i++) {
			BNField12[] gp16h = gp16i;
			gp16i = gp16[i];
			gp16i[0] = gp16h[0];
			for (int j = 1; j < 16; j++) {
				gp16i[j] = gp16h[j].square().square().square().square();
			}
		}
	}

	public BNField12 gPower(BigInteger k) {
		if (g == null) {
			throw new IllegalArgumentException("not initialized");
		}
		k = k.mod(bn.n);
		BNField12 A = Fp12_1;
		for (int i = 0, w = 0; i < gp16.length; i++, w >>>= 4) {
			if ((i & 7) == 0) {
				w = k.intValue();
				k = k.shiftRight(32);
			}
			A = A.multiply(gp16[i][w & 0xf]);
		}
		return A;
	}

	public String toString() {
		return "Bilinear pairing over " + E + " and " + E2;
	}
}
