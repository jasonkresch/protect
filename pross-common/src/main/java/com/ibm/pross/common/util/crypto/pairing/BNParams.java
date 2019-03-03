/**
 * BNParams.java
 *
 * Parameters for Barreto-Naehrig (BN) pairing-friendly elliptic curves.
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

public class BNParams {

	/**
	 * Convenient BigInteger constants
	 */
	static final BigInteger _0 = BigInteger.valueOf(0L), _1 = BigInteger.valueOf(1L), _2 = BigInteger.valueOf(2L),
			_3 = BigInteger.valueOf(3L), _4 = BigInteger.valueOf(4L), _5 = BigInteger.valueOf(5L),
			_6 = BigInteger.valueOf(6L), _7 = BigInteger.valueOf(7L), _9 = BigInteger.valueOf(9L),
			_24 = BigInteger.valueOf(24L);

	/**
	 * Rabin-Miller certainty used for primality testing
	 */
	static final int PRIMALITY_CERTAINTY = 20;

	/**
	 * Invalid parameters error message
	 */
	public static final String invalidParams = "The specified parameters do not properly define a suitable BN curve";

	/**
	 * Field size in bits.
	 */
	int m;

	public static int[] validBitsRange = { 34, 48, 56, 64, 72, 80, 88, 96, 104, 112, 120, 128, 136, 144, 152, 158, 160,
			168, 176, 184, 190, 192, 200, 208, 216, 222, 224, 232, 240, 248, 254, 256, 264, 272, 280, 288, 296, 304,
			312, 318, 320, 328, 336, 344, 352, 360, 368, 376, 382, 384, 392, 400, 408, 416, 424, 432, 440, 446, 448,
			456, 464, 472, 480, 488, 496, 504, 512 };

	/**
	 * BN index -- the curve BN(u) is defined by the following parameters:
	 *
	 * t = 6*u^2 + 1 p = 36*u^4 + 36*u^3 + 24*u^2 + 6*u + 1 n = 36*u^4 + 36*u^3 +
	 * 18*u^2 + 6*u + 1
	 *
	 * BN(u)/GF(p): y^2 = x^3 + b, #BN(u)(GF(p)) = n, n = p + 1 - t.
	 *
	 * Restrictions: p = 3 (mod 4) and p = 4 (mod 9).
	 */
	BigInteger u;

	/**
	 * Size of the underlying finite field GF(p)
	 */
	BigInteger p;

	/**
	 * Trace of the Frobenius endomorphism
	 **/
	BigInteger t;

	/**
	 * Curve equation coefficient E: y^2 = x^3 + b
	 */
	int b;

	/**
	 * Primitive cube root of unity mod p
	 */
	BigInteger zeta;

	BigInteger zeta0;
	BigInteger zeta1;

	/**
	 * (t - 1)^2 mod n, order of eta (also called twisted ate) pairing for BN curves
	 */
	BigInteger rho;

	/**
	 * Order of optimal pairing: (6*u + 2)
	 */
	BigInteger optOrd;

	BigInteger sqrtExponent;
	BigInteger cbrtExponent;
	BigInteger sqrtExponent2;
	BigInteger cbrtExponent2;
	BigInteger invSqrtMinus2;

	/**
	 * Prime curve order
	 */
	BigInteger n;

	/**
	 * Cofactor of twist (curve order = ht*n)
	 */
	BigInteger ht;

	BigInteger sigma;
	BigInteger zeta0sigma;
	BigInteger zeta1sigma;

	BigInteger[] omega;

	BNField2 sqrtI;
	BNField2 Fp2_0;
	BNField2 Fp2_1;
	BNField2 Fp2_i;
	BNField12 Fp12_0;
	BNField12 Fp12_1;

	BigInteger[] latInv;
	BigInteger[][] latRed;

	public boolean equals(Object o) {
		if (!(o instanceof BNParams)) {
			return false;
		}
		return (u.compareTo(((BNParams) o).u) == 0);
	}

	/**
	 * Compute BN parameters for a given field size, which must be a multiple of 8
	 * between 48 and 512 (inclusive).
	 *
	 * The BN parameter u is the largest one with the smallest possible Hamming
	 * weight, leading to a field prime p satisfying both p = 3 (mod 4) and p = 4
	 * (mod 9), speeding up the computation of square and cube roots in both F_p and
	 * F_{p^2}. Besides, for i \in F_{p^2} such that i^2 + 1 = 0, the element v = 1
	 * + i is neither a square nor a cube, so that one can represent F_{p^(2m)} as
	 * F_{p^2}[z]/(z^m - 1/v) or F_{p^2}[z]/(z^m - v) for m = 2, 3, 6.
	 *
	 * The standard curve is E(F_p): y^2 = x^3 + 3, whose default generator is G =
	 * (1, 2). Its (sextic) twist is E'(F_{p^2}): y'^2 = x'^3 + 3v, whose default
	 * generator has the form G' = [p-1+t]*(1, y') for some y'.
	 *
	 * The standard isomorphism psi: E'(F_{p^2}) -> E(F_{p^12}) is defined as
	 * psi(x', y') = (x'*z^2, y'*z^3) for the first representation of F_{p^12}
	 * above, and as psi(x', y') = (x'/z^2, y'/z^3) = (x'*z^4/v, y'*z^3/v) for the
	 * second representation.
	 */
	public BNParams(int fieldBits) {
		m = fieldBits;
		b = 3; // default assumption; corrected below on demand
		switch (fieldBits) {

		case 34: ////////////////////////////////
			b = 2;
			u = new BigInteger("-10000101", 2); // Hamming weight 3
			break;

		case 48:
			u = new BigInteger("-11001011001", 2); // Hamming weight 6
			break;
		case 56:
			u = new BigInteger("1011001111011", 2); // Hamming weight 9
			break;
		case 64:
			u = new BigInteger("110010000111111", 2); // Hamming weight 9
			break;
		case 72:
			u = new BigInteger("10110000111001011", 2); // Hamming weight 9
			break;
		case 80:
			u = new BigInteger("1101000010001011011", 2); // Hamming weight 9
			break;
		case 88:
			u = new BigInteger("-110000011000001110001", 2); // Hamming weight 8
			break;
		case 96:
			u = new BigInteger("11010000000000000010111", 2); // Hamming weight 7
			break;
		case 104:
			u = new BigInteger("1101000000000000000100011", 2); // Hamming weight 6
			break;
		case 112:
			u = new BigInteger("-110000001100001000000000001", 2); // Hamming weight 6
			break;
		case 120:
			u = new BigInteger("11000000100000000100100000011", 2); // Hamming weight 7
			break;
		case 128:
			u = new BigInteger("-1100111000000000000000000000001", 2); // Hamming weight 6
			break;
		case 136:
			u = new BigInteger("-110000100000000000000001100000001", 2); // Hamming weight 6
			break;
		case 144:
			u = new BigInteger("-10110010000000010000000000000000001", 2); // Hamming weight 6
			break;
		case 152:
			u = new BigInteger("-1100100001000000100000000000000000001", 2); // Hamming weight 6
			break;

		case 158: ////////////////////////////////
			b = 2;
			u = new BigInteger("100000000000000100000000000000000100011", 2); // Hamming weight 5
			// u = new BigInteger("-100000010000000100000000010000000000001", 2); // Hamming
			// weight 5
			break;

		case 160:
			// u = new BigInteger("110100001000000000000100010000000000011", 2); // *** ISO,
			// Hamming weight 8
			u = new BigInteger("-110010001000000010000000000000001000001", 2); // Hamming weight 7
			break;
		case 168:
			u = new BigInteger("-11001000000000000000000010000001000000001", 2); // Hamming weight 6
			break;
		case 176:
			u = new BigInteger("-1100100100000000000000000010000000000000001", 2); // Hamming weight 6
			break;
		case 184:
			u = new BigInteger("-110000001100000000000000000000001000000000001", 2); // Hamming weight 6
			break;

		case 190: ////////////////////////////////
			b = 2;
			u = new BigInteger("-10000000010000100100000000000000000000000000001", 2); // Hamming weight 5
			// u = new BigInteger("10000000010000000000000000000000000000001000011", 2); //
			// Hamming weight 5
			break;

		case 192:
			// u = new BigInteger("11000000000000000001000000000000000010000010011", 2); //
			// *** ISO, Hamming weight 7
			u = new BigInteger("-11000000000000000000010010000000000010000000001", 2); // Hamming weight 6
			break;
		case 200:
			u = new BigInteger("-1101000000000000000000001000000000000010000000001", 2); // Hamming weight 6
			break;
		case 208:
			u = new BigInteger("110000000000000000000000000000000000000000100000011", 2); // Hamming weight 5
			break;
		case 216:
			u = new BigInteger("-11000000000000000010000000000000000000000000000000001", 2); // Hamming weight 4
			break;

		case 222: ////////////////////////////////
			b = 2;
			u = new BigInteger("1000010000000000010000000000000000000000000000000000011", 2); // Hamming weight 5
			// u = new BigInteger("1000000000000000000000000000000000000000100100000000011",
			// 2); // Hamming weight 5
			break;

		case 224:
			// u = new BigInteger("1100000000000000000000100000001000000000000001000000011",
			// 2); // *** ISO, Hamming weight 7
			u = new BigInteger("-1100000100000000000000000010000000100000000000000000001", 2); // Hamming weight 6
			break;
		case 232:
			u = new BigInteger("-110000000100000000100000000000000000000000000010000000001", 2); // Hamming weight 6
			break;
		case 240:
			u = new BigInteger("-11000100000000000000000000000010000000000000000000100000001", 2); // Hamming weight 6
			break;
		case 248:
			u = new BigInteger("-1100010000001000000000100000000000000000000000000000000000001", 2); // Hamming weight 6
			break;

		case 254: ////////////////////////////////
			b = 2;
			u = new BigInteger("-100000010000000000000000000000000000000000000000000000000000001", 2); // Hamming weight
																										// 3
			// u = new
			// BigInteger("-100000010000000000000000000000000000000001000000000001000000001",
			// 2); // Hamming weight 5
			break;

		case 256:
			u = new BigInteger("110000010000000000000000000000000000000000001000000000001000011", 2); // *** ISO,
																										// Hamming
																										// weight 7
			// u = new
			// BigInteger("-110000100000100000000001000000000000000000000000000000000000001",
			// 2); // Hamming weight 6
			break;
		case 264:
			u = new BigInteger("11000000000000000001000000000000000000000000000000000100000000011", 2); // Hamming
																										// weight 6
			break;
		case 272:
			u = new BigInteger("1100000100000000000010000000000000000000000000000000000000001000011", 2); // Hamming
																											// weight 7
			break;
		case 280:
			u = new BigInteger("-110001000000000000000000000000100000100000000000000000000000000000001", 2); // Hamming
																												// weight
																												// 6
			break;
		case 288:
			u = new BigInteger("11000000000000000000000000000000000100000001000000000000000000000000011", 2); // Hamming
																												// weight
																												// 6
			break;
		case 296:
			u = new BigInteger("-1100000000000100000000000000100000000000000000000000000000000000000010001", 2); // Hamming
																													// weight
																													// 6
			break;
		case 304:
			u = new BigInteger("110000000000000100000000000000000000000000000000000000000001000000000000011", 2); // Hamming
																													// weight
																													// 6
			break;
		case 312:
			u = new BigInteger("-11000000000000001000000000000000000000000001000010000000000000000000000000001", 2); // Hamming
																														// weight
																														// 6
			break;

		case 318: ////////////////////////////////
			b = 2;
			u = new BigInteger("1000000000000000100000000000000000000000000000000000000000000000000000000000011", 2); // Hamming
																														// weight
																														// 4
			// u = new
			// BigInteger("-1000000000000000100000000000000000000000000000000000000000000000001000000010001",
			// 2); // Hamming weight 5
			break;

		case 320:
			u = new BigInteger("-1100000001000000000000000000000000000000000010001000000000000000000000000000001", 2); // Hamming
																														// weight
																														// 6
			break;
		case 328:
			u = new BigInteger("-110000000000100000000000000000000000000000000000000010000000000100000000000000001", 2); // Hamming
																															// weight
																															// 6
			break;
		case 336:
			u = new BigInteger("-11000000000000000000000000000000000000010000000000000000000100000000000000000000001",
					2); // Hamming weight 5
			break;
		case 344:
			u = new BigInteger("-1100100000000000000000000000000000000000010000001000000000000000000000000000000000001",
					2); // Hamming weight 6
			break;
		case 352:
			u = new BigInteger(
					"-110000100000000000000000000000000000001000000000000000000000010000000000000000000000001", 2); // Hamming
																													// weight
																													// 6
			break;
		case 360:
			u = new BigInteger(
					"-11000100001000000000000000000000000000000000000000001000000000000000000000000000000000001", 2); // Hamming
																														// weight
																														// 6
			break;
		case 368:
			u = new BigInteger(
					"-1100000000000000001010000000000000000000000001000000000000000000000000000000000000000000001", 2); // Hamming
																														// weight
																														// 6
			break;
		case 376:
			u = new BigInteger(
					"-110000000010000000000100000000000000000000000000000000000000000000000000000000000000100000001",
					2); // Hamming weight 6
			break;

		case 382: ////////////////////////////////
			b = 2;
			u = new BigInteger(
					"-10000000000000000010001000000000000000000000000000000000000000000000000000000000000000000000001",
					2); // Hamming weight 4
			break;

		case 384:
			// u = new
			// BigInteger("11001000000000000010000000000000000000000000000000000000000000000100000000000000000000000000011",
			// 2); // *** ISO, Hamming weight 7
			u = new BigInteger(
					"-11000000000000000000000000000000000001000000000000000000000000000000000000000001000000000000001",
					2); // Hamming weight 5
			break;
		case 392:
			u = new BigInteger(
					"-1100100001000000000000000000000000000000000000000000000000000000000000000000100000000000000000001",
					2); // Hamming weight 6
			break;
		case 400:
			u = new BigInteger(
					"110000000000000000000000000000000000000000000000000000000000000000000000000000000100000001000000011",
					2); // Hamming weight 6
			break;
		case 408:
			u = new BigInteger(
					"-11000000000000010000000000000000000000000000000000000000000000000000000000000000000010000000000010001",
					2); // Hamming weight 6
			break;
		case 416:
			u = new BigInteger(
					"-1100100000000000000000000000000000010000000000000000000000000000001000000000000000000000000000000000001",
					2); // Hamming weight 6
			break;
		case 424:
			u = new BigInteger(
					"-110000000000000000000000000000100000000000010000000000000000000000001000000000000000000000000000000000001",
					2); // Hamming weight 6
			break;
		case 432:
			u = new BigInteger(
					"-11000000000000000000000000000000000000000000000000010010000000000000000000000000000000000010000000000000001",
					2); // Hamming weight 6
			break;
		case 440:
			u = new BigInteger(
					"-1100100000000000000000000000000000000000001000000000000000000000000000010000000000000000000000000000000000001",
					2); // Hamming weight 6
			break;

		case 446: ////////////////////////////////
			b = 2;
			u = new BigInteger(
					"-100000000000000000000000000000000000000000000010000000001000000000000000000000000000000000000000000000000000001",
					2); // Hamming weight 4
			break;

		case 448:
			u = new BigInteger(
					"110000000000000000000000000000000000000000000000000000000000000000000000000000000100000000000001000000000000011",
					2); // Hamming weight 6
			break;
		case 456:
			u = new BigInteger(
					"-11000000000000000000000000000100000000000000000000000000000000000000000000010000000000000000000000000000000000001",
					2); // Hamming weight 5
			break;
		case 464:
			u = new BigInteger(
					"-1100100000000000000000000000000000011000000000000000000000000000000000000000000000000000000000000000000000000000001",
					2); // Hamming weight 6
			break;
		case 472:
			u = new BigInteger(
					"-110000001000000000000000000000000000000000000000000000000000000000000000010000000000000000000000100000000000000000001",
					2); // Hamming weight 6
			break;
		case 480:
			u = new BigInteger(
					"-11000000000000000100000000010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001",
					2); // Hamming weight 5
			break;
		case 488:
			u = new BigInteger(
					"-1100000001000000000000000000000000000000000000000010000000000000000000000000000000001000000000000000000000000000000000001",
					2); // Hamming weight 6
			break;
		case 496:
			u = new BigInteger(
					"-110010000000000000000000000100000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000001",
					2); // Hamming weight 6
			break;
		case 504:
			u = new BigInteger(
					"-11010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000100000000000000001",
					2); // Hamming weight 5
			break;
		case 512:
			// u = new
			// BigInteger("1100001000000000000000000000000000000000000000000000000000000000000000000000000000010000000000000000000000001000000000000000011",
			// 2); // *** ISO, Hamming weight 7
			u = new BigInteger(
					"-1100001000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000000000000000000000010000000001",
					2); // Hamming weight 6
			break;
		default:
			throw new IllegalArgumentException(
					invalidParams + ": " + "Field size in bits must be a multiple of 8 between 56 and 512");
		}
		// p = 36*u^4 + 36*u^3 + 24*u^2 + 6*u + 1 = (((u + 1)*6*u + 4)*u + 1)*6*u + 1
		p = u.add(_1).multiply(_6.multiply(u)).add(_4).multiply(u).add(_1).multiply(_6.multiply(u)).add(_1);
		assert (p.mod(_4).intValue() == 3);
		// assert (p.mod(_9).intValue() == 4);
		assert (p.isProbablePrime(PRIMALITY_CERTAINTY));
		t = _6.multiply(u).multiply(u).add(_1); // 6*u^2 + 1
		ht = p.subtract(_1).add(t);
		// n = 36*u^4 + 36*u^3 + 18*u^2 + 6*u + 1
		n = p.add(_1).subtract(t);
		assert (n.isProbablePrime(PRIMALITY_CERTAINTY));
		// zeta = 18*u^3 + 18*u^2 + 9*u + 1;
		zeta = _9.multiply(u).multiply(u.shiftLeft(1).multiply(u.add(_1)).add(_1)).add(_1);
		// System.out.println("zeta = " + zeta);
		zeta0 = zeta;
		zeta1 = zeta.add(_1);
		// rho = |36*u^3 + 18*u^2 + 6*u + 1| = |6*u*(3*u*(2*u + 1) + 1) + 1)|;
		rho = _6.multiply(u).multiply(_3.multiply(u).multiply(u.shiftLeft(1).add(_1)).add(_1)).add(_1);
		// *
		if (rho.signum() < 0) {
			rho = rho.negate();
		}
		// */
		optOrd = _6.multiply(u).add(_2);
		// *
		if (optOrd.signum() < 0) {
			optOrd = optOrd.negate();
		}
		// */
		sqrtExponent = p.add(_1).shiftRight(2); // (p + 1)/4
		cbrtExponent = p.add(p).add(_1).divide(_9); // (2*p + 1)/9
		sqrtExponent2 = p.multiply(p).add(_7).shiftRight(4); // (p^2 + 7)/16
		cbrtExponent2 = p.multiply(p).add(_2).divide(_9); // (p^2 + 2)/9
		sigma = p.subtract(_4).modPow(p.subtract(_1).subtract(p.add(_5).divide(_24)), p); // (-1/4)^((p+5)/24)
		zeta0sigma = zeta0.multiply(sigma).mod(p);
		zeta1sigma = zeta1.multiply(sigma).mod(p);

		// 2*sigma^2 = -zeta
		// -2*sigma^3 = -sigma*(2*sigma^2) = sigma*zeta
		// -4*sigma^4 = zeta+1
		// -4*sigma^5 = -4*sigma^4*sigma = (zeta+1)*sigma
		// 8*sigma^6 = -1
		// -16*sigma^9 = -2*sigma^3*(8*sigma^6) = 2*sigma^3
		invSqrtMinus2 = p.subtract(_2).modPow(p.subtract(_1).subtract(p.add(_1).shiftRight(2)), p); // 1/sqrt(-2) =
																									// (-2)^{-(p+1)/4}
		sqrtI = new BNField2(this, invSqrtMinus2,
				(invSqrtMinus2.signum() != 0) ? p.subtract(invSqrtMinus2) : invSqrtMinus2, false); // sqrt(i) = (1 -
																									// i)/sqrt(-2)
		Fp2_0 = new BNField2(this, _0);
		Fp2_1 = new BNField2(this, _1);
		Fp2_i = new BNField2(this, _0, _1, false);
		Fp12_0 = new BNField12(this, _0);
		Fp12_1 = new BNField12(this, _1);

		latInv = new BigInteger[4];
		latInv[0] = u.shiftLeft(1).add(_3).multiply(u).add(_1); // 2*u^2 + 3*u + 1 = (2*u + 3)*u + 1
		latInv[1] = u.multiply(_3).add(_2).multiply(u).multiply(u).shiftLeft(2).add(u); // 12*u^3 + 8*u^2 + u = ((3*u +
																						// 2)*u)*4*u + u
		latInv[2] = u.multiply(_3).add(_2).multiply(u).multiply(u).shiftLeft(1).add(u); // 6*u^3 + 4*u^2 + u = ((3*u +
																						// 2)*u)*2*u + u
		latInv[3] = u.multiply(u).shiftLeft(1).add(u).negate(); // -(2*u^2 + u)

		latRed = new BigInteger[4][4];
		/*
		 * u+1, u, u, -2*u, 2*u+1, -u, -(u+1), -u, 2*u, 2*u+1, 2*u+1, 2*u+1, u-1, 4*u+2,
		 * -2*u+1, u-1
		 */

		latRed[0][0] = u.add(_1);
		latRed[0][1] = u;
		latRed[0][2] = u;
		latRed[0][3] = u.shiftLeft(1).negate();

		latRed[1][0] = u.shiftLeft(1).add(_1);
		latRed[1][1] = u.negate();
		latRed[1][2] = u.add(_1).negate();
		latRed[1][3] = u.negate();

		latRed[2][0] = u.shiftLeft(1);
		latRed[2][1] = u.shiftLeft(1).add(_1);
		latRed[2][2] = u.shiftLeft(1).add(_1);
		latRed[2][3] = u.shiftLeft(1).add(_1);

		latRed[3][0] = u.subtract(_1);
		latRed[3][1] = u.shiftLeft(2).add(_2);
		latRed[3][2] = u.shiftLeft(1).negate().add(_1);
		latRed[3][3] = u.subtract(_1);
	}

	/**
	 * Compute the quadratic character of v, i.e. (v/p) for prime p.
	 */
	public int legendre(BigInteger v) {
		// return v.modPow(p.shiftRight(1), p).add(_1).compareTo(p) == 0 ? -1 : 1; //
		// v^((p-1)/2) mod p = (v/p) for prime p
		int J = 1;
		BigInteger x = v, y = p;
		if (x.signum() < 0) {
			x = x.negate();
			if (y.testBit(0) && y.testBit(1)) { // y = 3 (mod 4)
				J = -J;
			}
		}
		while (y.compareTo(_1) > 0) {
			x = x.mod(y);
			if (x.compareTo(y.shiftRight(1)) > 0) {
				x = y.subtract(x);
				if (y.testBit(0) && y.testBit(1)) { // y = 3 (mod 4)
					J = -J;
				}
			}
			if (x.signum() == 0) {
				x = _1;
				y = _0;
				J = 0;
				break;
			}
			while (!x.testBit(0) && !x.testBit(1)) { // 4 divides x
				x = x.shiftRight(2);
			}
			if (!x.testBit(0)) { // 2 divides x
				x = x.shiftRight(1);
				if (y.testBit(0) && (y.testBit(1) == !y.testBit(2))) { // y = �3 (mod 8)
					J = -J;
				}
			}
			if (x.testBit(0) && x.testBit(1) && y.testBit(0) && y.testBit(1)) { // x = y = 3 (mod 4)
				J = -J;
			}
			BigInteger t = x;
			x = y;
			y = t; // switch x and y
		}
		return J;
	}

	/**
	 * Compute a square root of v (mod p).
	 *
	 * @return a square root of v (mod p) if one exists, or null otherwise.
	 */
	BigInteger sqrt(BigInteger v) {
		if (v.signum() == 0) {
			return _0;
		}
		// case I: p = 3 (mod 4):
		if (p.testBit(1)) {
			BigInteger r = v.modPow(p.shiftRight(2).add(_1), p);
			// test solution:
			return r.multiply(r).subtract(v).mod(p).signum() == 0 ? r : null;
		}
		// case II: p = 5 (mod 8):
		if (p.testBit(2)) {
			BigInteger twog = v.shiftLeft(1).mod(p);
			BigInteger gamma = twog.modPow(p.shiftRight(3), p);
			BigInteger i = twog.multiply(gamma).multiply(gamma).mod(p);
			BigInteger r = v.multiply(gamma).multiply(i.subtract(_1)).mod(p);
			// test solution:
			return r.multiply(r).subtract(v).mod(p).signum() == 0 ? r : null;
		}
		// case III: p = 9 (mod 16):
		if (p.testBit(3)) {
			BigInteger twou = p.shiftRight(2); // (p-1)/4
			BigInteger s0 = v.shiftLeft(1).modPow(twou, p); // (2v)^(2u) mod p
			BigInteger s = s0;
			BigInteger d = _1;
			BigInteger fouru = twou.shiftLeft(1);
			while (s.add(_1).compareTo(p) != 0) {
				d = d.add(_2);
				s = d.modPow(fouru, p).multiply(s0).mod(p);
			}
			BigInteger w = d.multiply(d).multiply(v).shiftLeft(1).mod(p);
			// assert (w.modPow(twou, p).add(_1).compareTo(p) == 0);
			BigInteger z = w.modPow(p.shiftRight(4), p); // w^((p-9)/16)
			BigInteger i = z.multiply(z).multiply(w).mod(p);
			BigInteger r = z.multiply(d).multiply(v).multiply(i.subtract(_1)).mod(p);
			// test solution:
			return r.multiply(r).subtract(v).mod(p).signum() == 0 ? r : null;
		}
		// case IV: p = 17 (mod 32):
		if (p.testBit(4)) {
			BigInteger twou = p.shiftRight(3); // (p-1)/8
			BigInteger s0 = v.shiftLeft(1).modPow(twou, p); // (2v)^(2u) mod p
			BigInteger s = s0;
			BigInteger d = _1;
			BigInteger fouru = twou.shiftLeft(1); // (p-1)/4
			while (s.add(_1).compareTo(p) != 0) {
				d = d.add(_2);
				s = d.modPow(fouru, p).multiply(s0).mod(p);
			}
			BigInteger w = d.multiply(d).multiply(v).shiftLeft(1).mod(p);
			// assert (w.modPow(twou, p).add(_1).compareTo(p) == 0);
			BigInteger z = w.modPow(p.shiftRight(5), p); // w^((p-17)/32)
			BigInteger i = z.multiply(z).multiply(w).mod(p);
			BigInteger r = z.multiply(d).multiply(v).multiply(i.subtract(_1)).mod(p);
			// test solution:
			return r.multiply(r).subtract(v).mod(p).signum() == 0 ? r : null;
		}
		// case V: p = 1 (mod 4, 8, 16, 32):
		if (v.compareTo(_4) == 0) {
			return _2;
		}
		BigInteger z = v.subtract(_4).mod(p);
		BigInteger t = _1;
		while (legendre(z) >= 0) {
			t = t.add(_1);
			z = v.multiply(t).multiply(t).subtract(_4).mod(p);
		}
		z = v.multiply(t).multiply(t).subtract(_2).mod(p);
		BigInteger r = lucas(z, p.shiftRight(2)).multiply(t.modInverse(p)).mod(p);
		// test solution:
		return r.multiply(r).subtract(v).mod(p).signum() == 0 ? r : null;
	}

	/**
	 * Compute a cube root of v (mod p) where p = 4 (mod 9).
	 *
	 * @return a cube root of v (mod p) if one exists, or null otherwise.
	 *
	 * @exception IllegalArgumentException if the size p of the underlying finite
	 *                                     field does not satisfy p = 4 (mod 9).
	 */
	public BigInteger cbrt(BigInteger v) {
		if (p.mod(_9).intValue() != 4) {
			throw new IllegalArgumentException(
					"This implementation is optimized for, and only works with, prime fields GF(p) where p = 4 (mod 9)");
		}
		if (v.signum() == 0) {
			return _0;
		}
		BigInteger r = v.modPow(cbrtExponent, p); // r = v^{(2p + 1)/9}
		return r.multiply(r).multiply(r).subtract(v).mod(p).signum() == 0 ? r : null;
	}

	/**
	 * Postl's algorithm to compute V_k(P, 1)
	 */
	private BigInteger lucas(BigInteger P, BigInteger k) {
		BigInteger d_1 = P;
		BigInteger d_2 = P.multiply(P).subtract(_2).mod(p);
		int l = k.bitLength() - 1; // k = \sum_{j=0}^l{k_j*2^j}
		for (int j = l - 1; j >= 1; j--) {
			if (k.testBit(j)) {
				d_1 = d_1.multiply(d_2).subtract(P).mod(p);
				d_2 = d_2.multiply(d_2).subtract(_2).mod(p);
			} else {
				d_2 = d_1.multiply(d_2).subtract(P).mod(p);
				d_1 = d_1.multiply(d_1).subtract(_2).mod(p);
			}
		}
		return (k.testBit(0)) ? d_1.multiply(d_2).subtract(P).mod(p) : d_1.multiply(d_1).subtract(_2).mod(p);
	}

	public static BigInteger randomBigInteger(int k, SecureRandom rnd) {
		return new BigInteger(k, rnd);
	}

	/**
	 * Compute the quadratic character of a, i.e. the legendre symbol of a
	 *
	 */
	private static BigInteger chi_q(BigInteger a, BNParams bn) {

		BigInteger arg = a.mod(bn.p);
		if (arg.equals(BigInteger.ZERO)) {
			System.out.println("argument is zero in F_p!");
			return _0;
		}
		return bn.legendre(arg) == 1 ? _1 : _1.negate();
	}

	/**
	 * Hashing to G1 (BNPoint) for BN curves This method is designed only for
	 * generators G = (1,sqrt(1+b))
	 *
	 * @param t   t \in \F_p* is the value to be encoded into a BNPoint
	 * @param bn  The underlying BNParams
	 * @param E   The underlying BN elliptic curve
	 * @param rnd A Secure Random value
	 */
	public static BNPoint SWEncBN(BigInteger t, BNParams bn, BNCurve E, SecureRandom rnd) {

		System.out.println("-----------------");

		// Check some requirements
		// if (!bn.p.mod(new BigInteger("36")).equals(new BigInteger("31"))) {
		// System.out.println("Prime p does not satisfy 31 mod 36!");
		// return null;
		// }
		if (!bn.p.mod(new BigInteger("12")).equals(new BigInteger("7"))) {
			System.out.println("Prime p does not satisfy 7 mod 12!");
			return null;
		}
		if (!bn.p.mod(new BigInteger("4")).equals(new BigInteger("3"))) {
			System.out.println("Prime p does not satisfy 3 mod 4!");
			return null;
		}
		if (!bn.p.mod(new BigInteger("3")).equals(new BigInteger("1"))) {
			System.out.println("Prime p does not satisfy 3 mod 4!");
			return null;
		}
		if (!E.G.x.equals(_1.mod(bn.p))) {
			System.out.println("The x coordinate of the generator G is not 1!");
			return null;
		}

		BigInteger sqrtExponent = bn.p.add(_1).shiftRight(2); // (q + 1)/4

		// s := sqrt(-3)
		// w = s.t / (-1 + b + t^2)
		BigInteger s = _3.negate().modPow(sqrtExponent, bn.p);
		BigInteger st = s.multiply(t);
		BigInteger inv = E.b.subtract(_1).add(t.pow(2)).modInverse(bn.p);
		BigInteger w = st.multiply(inv).mod(bn.p);

		// j = (1 - s)/2
		BigInteger j = _1.subtract(s).shiftRight(1).mod(bn.p);

		// x1 = j + tw
		// x2 = 1 - x1
		// x3 = -1 + (1/w^2)
		BigInteger x1 = j.add(t.multiply(w)).mod(bn.p);
		BigInteger x2 = _1.subtract(x1).mod(bn.p);
		BigInteger x3 = w.pow(2).modInverse(bn.p).subtract(_1).mod(bn.p);

		// r1,r2,r3 <-(R) \F_q*
		BigInteger r1, r2, r3;
		do {
			r1 = randomBigInteger(bn.m, rnd).mod(bn.p);
			r2 = randomBigInteger(bn.m, rnd).mod(bn.p);
			r3 = randomBigInteger(bn.m, rnd).mod(bn.p);
		} while (r1.equals(_0) || r2.equals(_0) || r3.equals(_0));

		BigInteger alpha = chi_q(r1.pow(2).multiply(x1.pow(3).add(E.b)), bn);
		BigInteger beta = chi_q(r2.pow(2).multiply(x2.pow(3).add(E.b)), bn);

		BigInteger i = alpha.subtract(_1).multiply(beta).mod(_3).add(_1);

		// (xi,yi): coordinates for the mapped point
		BigInteger xi = null, yi = null;

		xi = i.equals(_1) ? x1 : i.equals(_2) ? x2 : x3;

		if (t.equals(BigInteger.ZERO)) {
			yi = BigInteger.ZERO;
		} else {
			yi = xi.pow(3).add(E.b).mod(bn.p).modPow(sqrtExponent, bn.p);

			if (chi_q(r3.pow(2).multiply(t), bn).equals(_1.negate())) {
				// System.out.println("invert y signal if r3^2*t is quadratic non-residue");
				yi = yi.negate();
			}
		}

		BNPoint pointMapped = null;
		try {
			pointMapped = new BNPoint(E, xi, yi);
		} catch (IllegalArgumentException e) {
			System.out.println("\ni=" + i);
			System.out.println("xi:" + xi + "\n");
			return null;
		}

		// System.out.println("\nThe hash of t=" + t + " is the point \n" +
		// pointMapped);
		return pointMapped;
	}

	public BigInteger getModulus() {
		return p;
	}

	public BigInteger getCurveOrder() {
		return n;
	}

}