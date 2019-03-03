/**
 * BNTests.java
 *
 * Simple tests for Barreto-Naehrig (BN) pairing-friendly elliptic curves.
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

import java.io.IOException;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Random;

public class BNTests {

	protected static final BigInteger _0 = BigInteger.valueOf(0L), _1 = BigInteger.valueOf(1L),
			_2 = BigInteger.valueOf(2L), _3 = BigInteger.valueOf(3L), _4 = BigInteger.valueOf(4L),
			_5 = BigInteger.valueOf(5L), _6 = BigInteger.valueOf(6L);

	/**
	 * Generic prototypes used in the BNPoint and BNPoint2 tests.
	 */
	BNPoint prototype;
	BNPoint2 prototype2;
	BNField12 prototype12;

	/**
	 * Create an instance of BNTests by providing prototypes for BNPoint and GF
	 * variables.
	 *
	 * This is a direct application of the "Prototype" design pattern as described
	 * by E. Gamma, R. Helm, R. Johnson and J. Vlissides in "Design Patterns -
	 * Elements of Reusable Object-Oriented Software", Addison-Wesley (1995), pp.
	 * 117-126.
	 *
	 * @param prototype the prototype for BNPoint instantiation
	 */
	public BNTests(BNPoint prototype, BNPoint2 prototype2, BNField12 prototype12) {
		this.prototype = prototype;
		this.prototype2 = prototype2;
		this.prototype12 = prototype12;
	}

	/**
	 * Perform a complete test suite on the BNCurve implementation
	 *
	 * @param iterations the desired number of iterations of the test suite
	 * @param random     the source of randomness for the various tests
	 */
	public void doTest(int iterations, SecureRandom rand, boolean verbose) {
		BNPoint w, x, y, z, ecZero;
		BigInteger m, n;
		int numBits = 256; // caveat: maybe using larger values is better
		System.out.println("Testing E(F_p) arithmetic...");
		long totalElapsed = -System.currentTimeMillis();
		for (int i = 0; i < iterations; i++) {
			if (verbose) {
				System.out.print("test #" + i);
			}
			long elapsed = -System.currentTimeMillis();
			// create random values from the prototype:
			x = prototype.randomize(rand);
			y = prototype.randomize(rand);
			z = prototype.randomize(rand);
			ecZero = prototype.E.infinity;
			m = new BigInteger(numBits, rand);
			n = new BigInteger(numBits, rand);

			// check cloning/comparison/pertinence:
			if (iterations == 1) {
				System.out.print("\nchecking cloning/comparison/pertinence");
			}
			if (!x.equals(x)) {
				throw new RuntimeException("Comparison failure");
			}
			if (verbose) {
				System.out.print(".");
			}
			if (!x.isOnSameCurve(x)) {
				throw new RuntimeException("Inconsistent pertinence self-comparison");
			}
			if (verbose) {
				System.out.print(".");
			}
			if (!x.E.contains(x)) {
				throw new RuntimeException("Inconsistent curve pertinence");
			}
			if (verbose) {
				System.out.print(".");
			}

			// check addition properties:
			if (iterations == 1) {
				System.out.print(" done.\nchecking addition properties");
			}
			if (!x.add(y).equals(y.add(x))) {
				throw new RuntimeException("x + y != y + x");
			}
			if (verbose) {
				System.out.print(".");
			}
			if (!x.add(ecZero).equals(x)) {
				throw new RuntimeException("x + 0 != x");
			}
			if (verbose) {
				System.out.print(".");
			}
			if (!x.add(x.negate()).isZero()) {
				throw new RuntimeException("x + (-x) != 0");
			}
			if (verbose) {
				System.out.print(".");
			}
			if (!x.add(y).add(z).equals(x.add(y.add(z)))) {
				throw new RuntimeException("(x + y) + z != x + (y + z)");
			}
			if (verbose) {
				System.out.print(".");
			}
			if (!x.negate().negate().equals(x)) {
				throw new RuntimeException("-(-x) != x");
			}

			// check scalar multiplication properties:
			if (iterations == 1) {
				System.out.print(" done.\nchecking scalar multiplication properties");
			}
			if (!x.multiply(BigInteger.valueOf(0L)).equals(ecZero)) {
				throw new RuntimeException("0*x != 0");
			}
			if (verbose) {
				System.out.print(".");
			}
			if (!x.multiply(BigInteger.valueOf(1L)).equals(x)) {
				throw new RuntimeException("1*x != x");
			}
			if (verbose) {
				System.out.print(".");
			}
			if (!x.multiply(BigInteger.valueOf(2L)).equals(x.twice(1))) {
				throw new RuntimeException("2*x != twice x");
			}
			if (verbose) {
				System.out.print(".");
			}
			if (!x.multiply(BigInteger.valueOf(2L)).equals(x.add(x))) {
				throw new RuntimeException("2*x != x + x");
			}
			if (verbose) {
				System.out.print(".");
			}
			if (!x.multiply(BigInteger.valueOf(-1L)).equals(x.negate())) {
				throw new RuntimeException("(-1)*x != -x");
			}
			if (verbose) {
				System.out.print(".");
			}
			if (!x.multiply(m.negate()).equals(x.negate().multiply(m))) {
				throw new RuntimeException("(-m)*x != m*(-x)");
			}
			if (verbose) {
				System.out.print(".");
			}
			if (!x.multiply(m.negate()).equals(x.multiply(m).negate())) {
				throw new RuntimeException("(-m)*x != -(m*x)");
			}
			if (verbose) {
				System.out.print(".");
			}
			if (!x.multiply(m.add(n)).equals(x.multiply(m).add(x.multiply(n)))) {
				throw new RuntimeException("(m + n)*x != m*x + n*x");
			}
			if (verbose) {
				System.out.print(".");
			}
			w = x.multiply(n).multiply(m);
			if (!w.equals(x.multiply(m).multiply(n))) {
				throw new RuntimeException("m*(n*x) != n*(m*x)");
			}
			if (verbose) {
				System.out.print(".");
			}
			if (!w.equals(x.multiply(m.multiply(n)))) {
				throw new RuntimeException("m*(n*x) != (m*n)*x");
			}
			// TODO: test point compression/expansion/conversion
			elapsed += System.currentTimeMillis();
			if (verbose) {
				System.out.println(" done; elapsed =  " + (float) elapsed / 1000 + " s.");
			}
		}
		totalElapsed += System.currentTimeMillis();
		// if (verbose) {
		System.out.println(" OK; all " + iterations + " tests done in " + (float) totalElapsed / 1000 + " s.");
		// }
	}

	/**
	 * Perform a complete test suite on the BNCurve2 implementation
	 *
	 * @param iterations the desired number of iterations of the test suite
	 * @param random     the source of randomness for the various tests
	 */
	public void doTest2(int iterations, SecureRandom rand, boolean verbose) {
		BNPoint2 w, x, y, z, ecZero;
		BigInteger m, n;
		int numBits = 256; // caveat: maybe using larger values is better
		System.out.println("Testing E'(F_{p^2}) arithmetic...");
		BNParams bn = prototype2.E.E.bn;
		long totalElapsed = -System.currentTimeMillis();
		for (int i = 0; i < iterations; i++) {
			if (verbose) {
				System.out.print("test #" + i);
			}
			long elapsed = -System.currentTimeMillis();
			// create random values from the prototype:
			x = prototype2.randomize(rand);
			y = prototype2.randomize(rand);
			z = prototype2.randomize(rand);
			ecZero = prototype2.E.infinity;
			m = new BigInteger(numBits, rand);
			n = new BigInteger(numBits, rand);

			// check cloning/comparison/pertinence:
			if (iterations == 1) {
				System.out.print("\nchecking cloning/comparison/pertinence");
			}
			if (!x.equals(x)) {
				throw new RuntimeException("Comparison failure");
			}
			if (verbose) {
				System.out.print(".");
			}
			if (!x.isOnSameCurve(x)) {
				throw new RuntimeException("Inconsistent pertinence self-comparison");
			}
			if (verbose) {
				System.out.print(".");
			}
			if (!x.E.contains(x)) {
				throw new RuntimeException("Inconsistent curve pertinence");
			}
			if (verbose) {
				System.out.print(".");
			}

			// check addition properties:
			if (iterations == 1) {
				System.out.print(" done.\nchecking addition properties");
			}
			if (!x.twice(1).equals(x.add(x))) {
				throw new RuntimeException("2*x != x + x");
			}
			if (!x.add(y).equals(y.add(x))) {
				throw new RuntimeException("x + y != y + x");
			}
			if (verbose) {
				System.out.print(".");
			}
			if (!x.add(ecZero).equals(x)) {
				throw new RuntimeException("x + 0 != x");
			}
			if (verbose) {
				System.out.print(".");
			}
			if (!x.add(x.negate()).isZero()) {
				throw new RuntimeException("x + (-x) != 0");
			}
			if (verbose) {
				System.out.print(".");
			}
			if (!x.add(y).add(z).equals(x.add(y.add(z)))) {
				throw new RuntimeException("(x + y) + z != x + (y + z)");
			}
			if (verbose) {
				System.out.print(".");
			}
			if (!x.negate().negate().equals(x)) {
				throw new RuntimeException("-(-x) != x");
			}

			// check scalar multiplication properties:
			if (iterations == 1) {
				System.out.print(" done.\nchecking scalar multiplication properties");
			}
			if (!x.multiply(BigInteger.valueOf(0L)).equals(ecZero)) {
				throw new RuntimeException("0*x != 0");
			}
			if (verbose) {
				System.out.print(".");
			}
			if (!x.multiply(BigInteger.valueOf(1L)).equals(x)) {
				throw new RuntimeException("1*x != x");
			}
			if (verbose) {
				System.out.print(".");
			}
			if (!x.multiply(BigInteger.valueOf(2L)).equals(x.twice(1))) {
				throw new RuntimeException("2*x != twice x");
			}
			if (verbose) {
				System.out.print(".");
			}
			if (!x.multiply(BigInteger.valueOf(2L)).equals(x.add(x))) {
				throw new RuntimeException("2*x != x + x");
			}
			if (verbose) {
				System.out.print(".");
			}
			if (!x.multiply(BigInteger.valueOf(-1L)).equals(x.negate())) {
				throw new RuntimeException("(-1)*x != -x");
			}
			if (verbose) {
				System.out.print(".");
			}
			if (!x.multiply(m.negate()).equals(x.negate().multiply(m))) {
				throw new RuntimeException("(-m)*x != m*(-x)");
			}
			if (verbose) {
				System.out.print(".");
			}
			if (!x.multiply(m.negate()).equals(x.multiply(m).negate())) {
				throw new RuntimeException("(-m)*x != -(m*x)");
			}
			if (verbose) {
				System.out.print(".");
			}
			if (!x.multiply(m.add(n)).equals(x.multiply(m).add(x.multiply(n)))) {
				throw new RuntimeException("(m + n)*x != m*x + n*x");
			}
			if (verbose) {
				System.out.print(".");
			}
			w = x.multiply(n).multiply(m);
			if (!w.equals(x.multiply(m).multiply(n))) {
				throw new RuntimeException("m*(n*x) != n*(m*x)");
			}
			if (verbose) {
				System.out.print(".");
			}
			if (!w.equals(x.multiply(m.multiply(n)))) {
				throw new RuntimeException("m*(n*x) != (m*n)*x");
			}
			if (!x.multiply(bn.p).equals(x.normalize().frobex(1))) {
				System.out.println();
				System.out.println("x^p    = " + x.multiply(bn.p));
				System.out.println("Phi(x) = " + x.normalize().frobex(1));
				throw new RuntimeException("inconsistent Frobenius");
			}
			if (!x.multiply(bn.p).multiply(bn.p).equals(x.normalize().frobex(2))) {
				throw new RuntimeException("inconsistent Frobenius");
			}
			if (!x.multiply(bn.p).multiply(bn.p).multiply(bn.p).equals(x.normalize().frobex(3))) {
				throw new RuntimeException("inconsistent Frobenius");
			}
			// TODO: test point compression/expansion/conversion
			elapsed += System.currentTimeMillis();
			if (verbose) {
				System.out.println(" done; elapsed =  " + (float) elapsed / 1000 + " s.");
			}
		}
		totalElapsed += System.currentTimeMillis();
		// if (verbose) {
		System.out.println(" OK; all " + iterations + " tests done in " + (float) totalElapsed / 1000 + " s.");
		// }
	}

	public void doFp12Test(int iterations, SecureRandom rand, boolean verbose) {
		BigInteger m, n;
		BNField12 f, g, h, z;
		int numBits = 256; // caveat: maybe using larger values is better
		System.out.println("Testing F_{p^12} arithmetic...");
		long totalElapsed = -System.currentTimeMillis();
		for (int i = 0; i < iterations; i++) {
			f = prototype12.randomize(rand);
			g = prototype12.randomize(rand);
			h = prototype12.randomize(rand);
			m = new BigInteger(numBits, rand);
			n = new BigInteger(numBits, rand);
			// addition/subtraction tests
			if (!f.add(prototype12.bn.Fp12_0).equals(f)) {
				throw new RuntimeException("Inconsistent Fp12 field addition");
			}
			if (!f.add(f.negate()).isZero()) {
				throw new RuntimeException("Inconsistent Fp12 field addition");
			}
			if (!f.subtract(g).equals(f.add(g.negate()))) {
				throw new RuntimeException("Inconsistent Fp12 field addition");
			}
			if (!f.subtract(g).negate().equals(g.subtract(f))) {
				throw new RuntimeException("Inconsistent Fp12 field addition");
			}
			if (!f.add(g).add(h).equals(f.add(g.add(h)))) {
				throw new RuntimeException("Inconsistent Fp12 field addition");
			}
			if (!f.add(g).equals(g.add(f))) {
				throw new RuntimeException("Inconsistent Fp12 field addition");
			}
			if (!f.add(g).subtract(g).equals(f)) {
				throw new RuntimeException("Inconsistent Fp12 field addition");
			}
			// multiplication tests
			if (!f.multiply(g).multiply(h).equals(f.multiply(g.multiply(h)))) {
				throw new RuntimeException("Inconsistent Fp12 field multiplication");
			}
			if (!f.multiply(prototype12.bn.Fp12_0).isZero()) {
				throw new RuntimeException("Inconsistent Fp12 field multiplication");
			}
			if (!f.multiply(prototype12.bn.Fp12_1).equals(f)) {
				throw new RuntimeException("Inconsistent Fp12 field multiplication");
			}
			if (!f.multiply(g).equals(g.multiply(f))) {
				throw new RuntimeException("Inconsistent Fp12 field multiplication");
			}
			if (!f.multiply(f).equals(f.square())) {
				throw new RuntimeException("Inconsistent Fp12 field multiplication");
			}
			// inversion tests
			z = f.inverse();
			if (!f.multiply(z).isOne()) {
				throw new RuntimeException("Inconsistent Fp12 field inversion");
			}
			if (!f.multiply(g.multiply(z)).equals(g)) {
				throw new RuntimeException("Inconsistent Fp12 field inversion");
			}
			// distribution tests
			if (!f.multiply(g.add(h)).equals(f.multiply(g).add(f.multiply(h)))) {
				throw new RuntimeException("Inconsistent Fp12 field distribution");
			}
			// exponentiation tests
			if (!f.exp(m).exp(n).equals(f.exp(n).exp(m))) {
				throw new RuntimeException("Inconsistent Fp12 field exponentiation");
			}
			if (!f.exp(m).exp(n).equals(f.exp(m.multiply(n)))) {
				throw new RuntimeException("Inconsistent Fp12 field exponentiation");
			}
			if (!f.exp(m).multiply(f.exp(n)).equals(f.exp(m.add(n)))) {
				throw new RuntimeException("Inconsistent Fp12 field exponentiation");
			}
			if (!f.frobenius().equals(f.exp(prototype12.bn.p))) {
				System.out.println("frob(f) = " + f.frobenius());
				System.out.println("f^p     = " + f.exp(prototype12.bn.p));
				throw new RuntimeException("Inconsistent Fp12 field Frobenius");
			}
			z = f;
			for (int j = 0; j < 6; j++) {
				if (!f.conjugate(j).equals(z)) {
					System.out.println("f.conjugate(" + j + ") = " + f.conjugate(j));
					System.out.println("f.exp((p^2)^" + j + ") = " + z);
					throw new RuntimeException("Inconsistent Fp12 field conjugate");
				}
				z = z.exp(prototype12.bn.p).exp(prototype12.bn.p);
			}
			if (verbose) {
				System.out.print(".");
			}
		}
		totalElapsed += System.currentTimeMillis();
		// if (verbose) {
		System.out.println(" OK; all " + iterations + " tests done in " + (float) totalElapsed / 1000 + " s.");
		// }
	}

	public static void benchmarks(int BM, int fieldBits) {
		byte[] randSeed = new byte[20];
		(new Random()).nextBytes(randSeed);

		SecureRandom rnd = new SecureRandom(randSeed);
		long elapsed;
		for (int i = fieldBits; i <= fieldBits; i++) {
			System.out.println("======== bits: " + i);
			BNParams sms = new BNParams(i);
			BNCurve E = new BNCurve(sms); // System.out.println(E);
			E.G.getSerializedTable();
			BNCurve2 E2 = new BNCurve2(E); // System.out.println(E2);
			BNPoint P = E.G;
			BNPoint2 Q = E2.Gt;
			BigInteger k = new BigInteger(i, rnd);
			BigInteger kk = new BigInteger(i, rnd);

			P = P.multiply(k); // just to get a point distinct from G
			P.getSerializedTable();
			BNPoint PP = P.multiply(k);

			System.out.println("Benchmarking BNPoint:");
			elapsed = -System.currentTimeMillis();
			for (int t = 0; t < BM; t++) {
				PP = P.multiply(k);
			}
			elapsed += System.currentTimeMillis();
			System.out.println("Elapsed time: " + (float) elapsed / BM + " ms.");
			System.out.println("P = " + P);
			//

			System.out.println("Benchmarking BNPoint2:");
			elapsed = -System.currentTimeMillis();
			for (int t = 0; t < BM; t++) {
				Q = Q.multiply(k);
			}
			elapsed += System.currentTimeMillis();
			System.out.println("Elapsed time: " + (float) elapsed / BM + " ms.");
			System.out.println("Q = " + Q);
			//
			if (P.isZero()) {
				throw new RuntimeException("LOGIC ERROR!");
			}
			if (Q.isZero()) {
				throw new RuntimeException("LOGIC ERROR!");
			}
			BNField12 f, g, a, b, c;
			BNPairing pair = new BNPairing(E2);

			System.out.println("\nTesting Eta Pairing:");
			g = pair.eta(E.G, E2.Gt);
			System.out.println("P   = " + E.G);
			System.out.println("n*P = " + E.G.multiply(sms.n));
			System.out.println("Q   = " + E2.Gt);
			System.out.println("n*Q = " + E2.Gt.multiply(sms.n));
			System.out.println("g   = " + g);
			System.out.println("g^n = " + g.exp(sms.n));
			a = pair.eta(E.G.twice(1), E2.Gt);
			b = pair.eta(E.G, E2.Gt.twice(1));
			c = g.square();
			System.out.println("eq? " + (a.equals(b) && b.equals(c)));
			for (int j = 0; j < 10; j++) {
				BigInteger m = new BigInteger(i, rnd);
				a = pair.eta(E.G.multiply(m), E2.Gt);
				b = pair.eta(E.G, E2.Gt.multiply(m));
				c = g.exp(m);
				System.out.println("eq? " + (a.equals(b) && b.equals(c)));
				if (!(a.equals(b) && b.equals(c)) || a.isOne()) {
					throw new RuntimeException("LOGIC ERROR!");
				}
			}
			//

			System.out.println("\nTesting Ate Pairing:");
			g = pair.ate(E2.Gt, E.G);
			System.out.println("P   = " + E.G);
			System.out.println("n*P = " + E.G.multiply(sms.n));
			System.out.println("Q   = " + E2.Gt);
			System.out.println("n*Q = " + E2.Gt.multiply(sms.n));
			System.out.println("g   = " + g);
			System.out.println("g^n = " + g.exp(sms.n));
			a = pair.ate(E2.Gt.twice(1), E.G);
			b = pair.ate(E2.Gt, E.G.twice(1));
			c = g.square();
			System.out.println("eq? " + (a.equals(b) && b.equals(c)));
			for (int j = 0; j < 10; j++) {
				BigInteger m = new BigInteger(i, rnd);
				a = pair.ate(E2.Gt.multiply(m), E.G);
				b = pair.ate(E2.Gt, E.G.multiply(m));
				c = g.exp(m);
				System.out.println("eq? " + (a.equals(b) && b.equals(c)));
				if (!(a.equals(b) && b.equals(c)) || a.isOne()) {
					System.out.println("a = " + a);
					System.out.println("b = " + b);
					System.out.println("c = " + c);
					throw new RuntimeException("LOGIC ERROR!");
				}
			}
			//

			/*
			 * if (g != null) { continue; } //
			 */

			System.out.println("Benchmarking Eta Pairing:");
			elapsed = -System.currentTimeMillis();
			f = null;
			for (int t = 0; t < BM; t++) {
				f = pair.eta(P, Q);
			}
			elapsed += System.currentTimeMillis();
			System.out.println("Elapsed time: " + (float) elapsed / BM + " ms.");
			System.out.println("f = " + f);
			//

			System.out.println("Benchmarking Ate Pairing:");
			f = null;
			elapsed = -System.currentTimeMillis();
			for (int t = 0; t < BM; t++) {
				f = pair.ate(Q, P);
			}
			elapsed += System.currentTimeMillis();
			System.out.println("Elapsed time: " + (float) elapsed / BM + " ms.");
			System.out.println("f = " + f);
			//

			System.out.println("Benchmarking BNField12 exponentiation:");
			f = pair.eta(P, Q);
			elapsed = -System.currentTimeMillis();
			for (int t = 0; t < BM; t++) {
				f = f.exp(k);
			}
			elapsed += System.currentTimeMillis();
			System.out.println("Elapsed time: " + (float) elapsed / BM + " ms.");
			//

			System.out.println("Benchmarking RSA-" + 6 * sms.p.bitLength() + " key generation");
			elapsed = -System.currentTimeMillis();
			BigInteger p = BigInteger.probablePrime(3 * sms.p.bitLength(), rnd);
			BigInteger q = BigInteger.probablePrime(3 * sms.p.bitLength(), rnd);
			BigInteger u = q.modInverse(p);
			BigInteger n = p.multiply(q);
			BigInteger phi = p.subtract(_1).multiply(q.subtract(_1));
			BigInteger e = BigInteger.valueOf(65537L);
			BigInteger d = e.modInverse(phi);
			BigInteger m = new BigInteger(6 * sms.p.bitLength(), rnd).mod(n);
			elapsed += System.currentTimeMillis();
			System.out.println("Elapsed time: " + (float) elapsed + " ms.");

			System.out.println("Benchmarking private RSA-" + 6 * sms.p.bitLength());
			elapsed = -System.currentTimeMillis();
			for (int t = 0; t < BM; t++) {
				// m = m.modPow(d, n);
				// chinese remainder theorem:
				BigInteger mp = m.modPow(d, p);
				BigInteger mq = m.modPow(d, q);
				m = mp.subtract(mq).multiply(u).mod(p).multiply(q).add(mq);
			}
			elapsed += System.currentTimeMillis();
			System.out.println("Elapsed time: " + (float) elapsed / BM + " ms.");

			System.out.println("Benchmarking public RSA-" + 6 * sms.p.bitLength());
			elapsed = -System.currentTimeMillis();
			for (int t = 0; t < BM; t++) {
				m = m.modPow(e, n);
			}
			elapsed += System.currentTimeMillis();
			System.out.println("Elapsed time: " + (float) elapsed / BM + " ms.");
			//

			//
			System.out.println("Benchmarking Barbosa-Farshim key validation:");
			f = pair.ate(Q, P);
			elapsed = -System.currentTimeMillis();
			for (int t = 0; t < BM; t++) {
				f = pair.ate(Q, P);
			}
			elapsed += System.currentTimeMillis();
			System.out.println("Elapsed time: " + (float) elapsed / BM + " ms.");

			System.out.println("Benchmarking BLMQ preprocessing:");
			elapsed = -System.currentTimeMillis();
			for (int t = 0; t < BM; t++) {
				PP = P.multiply(k);
			}
			elapsed += System.currentTimeMillis();
			System.out.println("Elapsed time: " + (float) elapsed / BM + " ms.");

			System.out.println("Benchmarking LXH preprocessing:");
			elapsed = -System.currentTimeMillis();
			for (int t = 0; t < BM; t++) {
				f = pair.ate(Q, P);
				f = pair.ate(Q, P);
			}
			elapsed += System.currentTimeMillis();
			System.out.println("Elapsed time: " + (float) elapsed / BM + " ms.");

			System.out.println("Benchmarking CLPKE-G_T preprocessing:");
			elapsed = -System.currentTimeMillis();
			for (int t = 0; t < BM; t++) {
				f = f.exp(k);
			}
			elapsed += System.currentTimeMillis();
			System.out.println("Elapsed time: " + (float) elapsed / BM + " ms.");
			//

			System.out.println("Benchmarking CLPKE preprocessing:");
			elapsed = -System.currentTimeMillis();
			for (int t = 0; t < BM; t++) {
				PP = P.multiply(k);
			}
			elapsed += System.currentTimeMillis();
			System.out.println("Elapsed time: " + (float) elapsed / BM + " ms.");

			System.out.println("Benchmarking BDCPS key validation:");
			elapsed = -System.currentTimeMillis();
			for (int t = 0; t < BM; t++) {
				f = pair.ate(Q, P);
				f = f.exp(k);
				f = f.exp(k);
				PP = P.multiply(k);
			}
			elapsed += System.currentTimeMillis();
			System.out.println("Elapsed time: " + (float) elapsed / BM + " ms.");

			System.out.println("Benchmarking BDCPS-G_1 key validation:");
			elapsed = -System.currentTimeMillis();
			for (int t = 0; t < BM; t++) {
				PP = P.multiply(k);
				f = pair.ate(Q, P);
				PP = P.simultaneous(k, kk, E.G);
				f = pair.ate(Q, P);
			}
			elapsed += System.currentTimeMillis();
			System.out.println("Elapsed time: " + (float) elapsed / BM + " ms.");
			//

			System.out.println("Benchmarking BSSCLSC key validation:");
			elapsed = -System.currentTimeMillis();
			for (int t = 0; t < BM; t++) {
				PP = P.multiply(k);
				PP = P.simultaneous(k, k, PP);
			}
			elapsed += System.currentTimeMillis();
			System.out.println("Elapsed time: " + (float) elapsed / BM + " ms.");

			System.out.println("----------------");

			System.out.println("Benchmarking Barbosa-Farshim signcryption:");
			elapsed = -System.currentTimeMillis();
			for (int t = 0; t < BM; t++) {
				f = f.exp(k);
				PP = P.multiply(k);
				PP = P.multiply(k);
				Q = Q.simultaneous(k, k, Q);
			}
			elapsed += System.currentTimeMillis();
			System.out.println("Elapsed time: " + (float) elapsed / BM + " ms.");

			System.out.println("Benchmarking BLMQ signcryption:");
			elapsed = -System.currentTimeMillis();
			for (int t = 0; t < BM; t++) {
				f = f.exp(k);
				PP = P.multiply(k);
				Q = Q.multiply(k);
			}
			elapsed += System.currentTimeMillis();
			System.out.println("Elapsed time: " + (float) elapsed / BM + " ms.");

			System.out.println("Benchmarking LXH signcryption:");
			elapsed = -System.currentTimeMillis();
			for (int t = 0; t < BM; t++) {
				f = f.exp(k);
				f = f.exp(k);
				PP = P.multiply(k);
				PP = P.multiply(k);
				PP = P.multiply(k);
			}
			elapsed += System.currentTimeMillis();
			System.out.println("Elapsed time: " + (float) elapsed / BM + " ms.");

			System.out.println("Benchmarking CLPKE-G_T encryption:");
			elapsed = -System.currentTimeMillis();
			for (int t = 0; t < BM; t++) {
				f = f.exp(k);
				f = f.exp(k);
				f = f.exp(k);
			}
			elapsed += System.currentTimeMillis();
			System.out.println("Elapsed time: " + (float) elapsed / BM + " ms.");
			//

			System.out.println("Benchmarking CLPKE encryption:");
			elapsed = -System.currentTimeMillis();
			for (int t = 0; t < BM; t++) {
				PP = P.multiply(k);
				PP = E.G.simultaneous(k, k, PP);
			}
			elapsed += System.currentTimeMillis();
			System.out.println("Elapsed time: " + (float) elapsed / BM + " ms.");

			System.out.println("Benchmarking BDCPS signcryption:");
			elapsed = -System.currentTimeMillis();
			for (int t = 0; t < BM; t++) {
				//BigInteger qq = k.modInverse(sms.n); // pure Zheng
				f = f.exp(k);
			}
			elapsed += System.currentTimeMillis();
			System.out.println("Elapsed time: " + (float) elapsed / BM + " ms.");

			System.out.println("Benchmarking BDCPS-G_1 signcryption:");
			elapsed = -System.currentTimeMillis();
			for (int t = 0; t < BM; t++) {
				//BigInteger qq = k.modInverse(sms.n); // pure Zheng
				PP = P.multiply(k);
			}
			elapsed += System.currentTimeMillis();
			System.out.println("Elapsed time: " + (float) elapsed / BM + " ms.");
			//

			System.out.println("Benchmarking BSSCLSC signcryption:");
			elapsed = -System.currentTimeMillis();
			for (int t = 0; t < BM; t++) {
				PP = E.G.multiply(k);
				PP = P.multiply(k);
			}
			elapsed += System.currentTimeMillis();
			System.out.println("Elapsed time: " + (float) elapsed / BM + " ms.");

			System.out.println("----------------");

			System.out.println("Benchmarking Barbosa-Farshim unsigncryption:");
			elapsed = -System.currentTimeMillis();
			for (int t = 0; t < BM; t++) {
				f = pair.ate(Q, P);
				f = pair.ate(Q, P);
				f = pair.ate(Q, P);
				f = pair.ate(Q, P);
				PP = P.multiply(k);
			}
			elapsed += System.currentTimeMillis();
			System.out.println("Elapsed time: " + (float) elapsed / BM + " ms.");

			System.out.println("Benchmarking BLMQ unsigncryption:");
			elapsed = -System.currentTimeMillis();
			for (int t = 0; t < BM; t++) {
				f = pair.ate(Q, P);
				f = pair.ate(Q, P);
				f = f.exp(k);
			}
			elapsed += System.currentTimeMillis();
			System.out.println("Elapsed time: " + (float) elapsed / BM + " ms.");

			System.out.println("Benchmarking LXH unsigncryption:");
			elapsed = -System.currentTimeMillis();
			for (int t = 0; t < BM; t++) {
				f = pair.ate(Q, P);
				f = pair.ate(Q, P);
				f = pair.ate(Q, P);
				f = pair.ate(Q, P);
				f = f.exp(k);
				f = f.exp(k);
			}
			elapsed += System.currentTimeMillis();
			System.out.println("Elapsed time: " + (float) elapsed / BM + " ms.");

			System.out.println("Benchmarking CLPKE-G_T decryption:");
			elapsed = -System.currentTimeMillis();
			for (int t = 0; t < BM; t++) {
				f = f.exp(k);
				f = f.exp(k);
				f = f.exp(k);
			}
			elapsed += System.currentTimeMillis();
			System.out.println("Elapsed time: " + (float) elapsed / BM + " ms.");
			//

			System.out.println("Benchmarking CLPKE decryption:");
			elapsed = -System.currentTimeMillis();
			for (int t = 0; t < BM; t++) {
				PP = P.multiply(k);
				PP = E.G.simultaneous(k, k, PP);
			}
			elapsed += System.currentTimeMillis();
			System.out.println("Elapsed time: " + (float) elapsed / BM + " ms.");

			System.out.println("Benchmarking BDCPS unsigncryption:");
			g = pair.ate(E2.Gt, E.G);
			elapsed = -System.currentTimeMillis();
			for (int t = 0; t < BM; t++) {
				f = f.exp(k).multiply(g.exp(kk));
			}
			elapsed += System.currentTimeMillis();
			System.out.println("Elapsed time: " + (float) elapsed / BM + " ms.");

			System.out.println("Benchmarking BDCPS-G_1 unsigncryption:");
			elapsed = -System.currentTimeMillis();
			for (int t = 0; t < BM; t++) {
				PP = E.G.simultaneous(k, kk, PP);
			}
			elapsed += System.currentTimeMillis();
			System.out.println("Elapsed time: " + (float) elapsed / BM + " ms.");
			//

			System.out.println("Benchmarking BSSCLSC unsigncryption:");
			elapsed = -System.currentTimeMillis();
			for (int t = 0; t < BM; t++) {
				PP = PP.multiply(k);
				PP = E.G.simultaneous(k, k, P);
			}
			elapsed += System.currentTimeMillis();
			System.out.println("Elapsed time: " + (float) elapsed / BM + " ms.");
		}
	}

	public static void main(String[] args) throws IOException, NoSuchAlgorithmException {
		byte[] randSeed = new byte[20];
		(new Random()).nextBytes(randSeed);
		// *
		for (int i = 0; i < randSeed.length; i++) {
			randSeed[i] = (byte) i;
		}
		// */
		//SecureRandom rnd = new SecureRandom(randSeed);

		for (int i = 0; i < BNParams.validBitsRange.length; i++) {
			if (BNParams.validBitsRange[i] != 254) {
				// continue;
			}
			System.out.println("\n======== bits: " + BNParams.validBitsRange[i]);
			BNParams bn = new BNParams(BNParams.validBitsRange[i]);
			System.out.println("u = " + bn.u + " (fam 1)");
			// BNParams bn = new BNParams(i, 2); System.out.println("u = " + bn.u + " (fam
			// 2)");
			BNCurve E = new BNCurve(bn);
			System.out.println(E);
			E.G.getSerializedTable();
			BNCurve2 Et = new BNCurve2(E);
			System.out.println(Et);
			//BNTests T = new BNTests(E.G, Et.Gt, E.bn.Fp12_0);
			// T.doTest(10, rnd, true);
			// T.doTest2(10, rnd, true);
			// T.doFp12Test(10, rnd, true);
			System.out.println("-----------------");
			BNPairing pair = new BNPairing(Et);
			System.out.println(pair);
			
			//BNField12 f, g, a, b, c;
			//BNPoint P = E.G;
			//BNPoint2 Q = Et.Gt;
			/*
			 * System.out.println("n*Q       = " + Q.multiply(bn.n).normalize());
			 * System.out.println("(t-1)*Q   = " +
			 * Q.multiply(bn.t.subtract(_1)).normalize()); System.out.println("p*Q       = "
			 * + Q.multiply(bn.p).normalize()); System.out.println("frobex(Q) = " +
			 * Q.frobex(1)); System.out.println("frobex(Q) in E' = " +
			 * Et.contains(Q.frobex(1))); System.out.println("p^2*Q     = " +
			 * Q.multiply(bn.p.pow(2)).normalize()); System.out.println("frobex(Q) = " +
			 * Q.frobex(2)); System.out.println("frobex(Q) in E' = " +
			 * Et.contains(Q.frobex(2))); System.out.println("p^3*Q     = " +
			 * Q.multiply(bn.p.pow(3)).normalize()); System.out.println("frobex(Q) = " +
			 * Q.frobex(3)); System.out.println("frobex(Q) in E' = " +
			 * Et.contains(Q.frobex(3))); Q = Q.multiply(_6); if
			 * (!Q.multiply(bn.p).equals(Q.normalize().frobex(1))) { throw new
			 * RuntimeException("inconsistent Frobenius"); } //
			 */
			/*
			 * System.out.println("Testing Tate pairing"); g = pair.tate(E.G, Et.Gt);
			 * //System.out.println("g = " + g); //System.out.println("g^n = " +
			 * g.exp(bn.n)); if (g.isZero()) { throw new
			 * RuntimeException("degeneracy error!"); } if (!g.exp(bn.n).isOne()) { throw
			 * new RuntimeException("G_T order error!"); } a =
			 * pair.tate(E.G.twice(1).normalize(), Et.Gt); b = pair.tate(E.G,
			 * Et.Gt.twice(1).normalize()); c = g.square(); System.out.println("bilinear? "
			 * + (a.equals(b) && b.equals(c))); if (!(a.equals(b) && b.equals(c)) ||
			 * a.isOne()) { System.out.println(">>>> a = " + a);
			 * System.out.println(">>>> b = " + b); System.out.println(">>>> c = " + c);
			 * throw new RuntimeException("Bilinearity error!"); } for (int j = 0; j < 10;
			 * j++) { BigInteger m = new BigInteger(BNParams.validBitsRange[i], rnd); a =
			 * pair.tate(E.G.multiply(m), Et.Gt); b = pair.tate(E.G, Et.Gt.multiply(m)); c =
			 * g.exp(m); System.out.println("bilinear? " + (a.equals(b) && b.equals(c))); if
			 * (!(a.equals(b) && b.equals(c)) || a.isOne()) { System.out.println(">>>> a = "
			 * + a); System.out.println(">>>> b = " + b); System.out.println(">>>> c = " +
			 * c); throw new RuntimeException("Bilinearity error!"); } } //
			 */
			/*
			 * System.out.println("Testing eta pairing"); g = pair.eta(E.G, Et.Gt);
			 * //System.out.println("g = " + g); //System.out.println("g^n = " +
			 * g.exp(bn.n)); if (g.isZero()) { throw new
			 * RuntimeException("degeneracy error!"); } if (!g.exp(bn.n).isOne()) { throw
			 * new RuntimeException("G_T order error!"); } a = pair.eta(E.G.twice(1),
			 * Et.Gt); b = pair.eta(E.G, Et.Gt.twice(1)); c = g.square();
			 * System.out.println("bilinear? " + (a.equals(b) && b.equals(c))); if
			 * (!(a.equals(b) && b.equals(c)) || a.isOne()) { System.out.println(">>>> a = "
			 * + a); System.out.println(">>>> b = " + b); System.out.println(">>>> c = " +
			 * c); throw new RuntimeException("Bilinearity error!"); } for (int j = 0; j <
			 * 10; j++) { BigInteger m = new BigInteger(BNParams.validBitsRange[i], rnd); a
			 * = pair.eta(E.G.multiply(m), Et.Gt); b = pair.eta(E.G, Et.Gt.multiply(m)); c =
			 * g.exp(m); System.out.println("bilinear? " + (a.equals(b) && b.equals(c))); if
			 * (!(a.equals(b) && b.equals(c)) || a.isOne()) { System.out.println(">>>> a = "
			 * + a); System.out.println(">>>> b = " + b); System.out.println(">>>> c = " +
			 * c); throw new RuntimeException("Bilinearity error!"); } } //
			 */
			/*
			 * System.out.println("Testing ate pairing"); g = pair.ate(Et.Gt, E.G);
			 * //System.out.println("g = " + g); //System.out.println("g^n = " +
			 * g.exp(bn.n)); if (g.isZero()) { throw new
			 * RuntimeException("degeneracy error!"); } if (!g.exp(bn.n).isOne()) { throw
			 * new RuntimeException("G_T order error!"); } a = pair.ate(Et.Gt.twice(1),
			 * E.G); b = pair.ate(Et.Gt, E.G.twice(1).normalize()); c = g.square();
			 * System.out.println("bilinear? " + (a.equals(b) && b.equals(c))); if
			 * (!(a.equals(b) && b.equals(c)) || a.isOne()) { System.out.println(">>>> a = "
			 * + a); System.out.println(">>>> b = " + b); System.out.println(">>>> c = " +
			 * c); throw new RuntimeException("Bilinearity error!"); } for (int j = 0; j <
			 * 10; j++) { BigInteger m = new BigInteger(i, rnd); a =
			 * pair.ate(Et.Gt.multiply(m), E.G); b = pair.ate(Et.Gt, E.G.multiply(m)); c =
			 * g.exp(m); System.out.println("bilinear? " + (a.equals(b) && b.equals(c))); if
			 * (!(a.equals(b) && b.equals(c)) || a.isOne()) { System.out.println(">>>> a = "
			 * + a); System.out.println(">>>> b = " + b); System.out.println(">>>> c = " +
			 * c); throw new RuntimeException("Bilinearity error!!"); } } //
			 */
			/*
			 * System.out.println("Testing optimal pairing"); g = pair.opt(Et.Gt, E.G);
			 * //System.out.println("g = " + g); //System.out.println("g^n = " +
			 * g.exp(bn.n)); if (g.isZero()) { throw new
			 * RuntimeException("degeneracy error!"); } if (!g.exp(bn.n).isOne()) { throw
			 * new RuntimeException("G_T order error!"); } a = pair.opt(Et.Gt.twice(1),
			 * E.G); b = pair.opt(Et.Gt, E.G.twice(1)); c = g.square();
			 * System.out.println("bilinear? " + (a.equals(b) && b.equals(c))); if
			 * (!(a.equals(b) && b.equals(c)) || a.isOne()) { System.out.println(">>>> a = "
			 * + a); System.out.println(">>>> b = " + b); System.out.println(">>>> c = " +
			 * c); throw new RuntimeException("Bilinearity error!!"); } for (int j = 0; j <
			 * 10; j++) { BigInteger m = new BigInteger(BNParams.validBitsRange[i], rnd); a
			 * = pair.opt(Et.Gt.multiply(m), E.G); b = pair.opt(Et.Gt, E.G.multiply(m)); c =
			 * g.exp(m); System.out.println("bilinear?? " + (a.equals(b) && b.equals(c)));
			 * if (!(a.equals(b) && b.equals(c)) || a.isOne()) {
			 * System.out.println(">>>> a = " + a); System.out.println(">>>> b = " + b);
			 * System.out.println(">>>> c = " + c); throw new
			 * RuntimeException("Bilinearity error!!"); } } //
			 */
			//BigInteger k = new BigInteger(BNParams.validBitsRange[i], rnd);
			/*
			 * P = P.multiply(k); P.getSerializedTable(); BNPoint PP = P;
			 * System.out.println("Benchmarking BNPoint:"); elapsed =
			 * -System.currentTimeMillis(); for (int t = 0; t < BM; t++) { PP =
			 * P.multiply(k); } elapsed += System.currentTimeMillis();
			 * System.out.println("Elapsed time: " + (float)elapsed/BM + " ms."); if
			 * (P.isZero()) { throw new RuntimeException("LOGIC ERROR!"); } //
			 */
			/*
			 * System.out.println("Benchmarking simultaneous:"); elapsed =
			 * -System.currentTimeMillis(); for (int t = 0; t < BM; t++) { PP =
			 * E.G.simultaneous(k, k, P); } elapsed += System.currentTimeMillis();
			 * System.out.println("Elapsed time: " + (float)elapsed/BM + " ms."); //
			 */
			/*
			 * System.out.println("Benchmarking BNPoint2:"); elapsed =
			 * -System.currentTimeMillis(); for (int t = 0; t < BM; t++) { BNPoint2 Q2 =
			 * Q.multiply(k); //BNPoint2 Q2 = Q.glv(k.negate()); //if
			 * (!Q2.equals(Q.multiply(k.negate()))) { throw new RuntimeException("Oops!"); }
			 * Q = Q2; } elapsed += System.currentTimeMillis();
			 * System.out.println("Elapsed time: " + (float)elapsed/BM + " ms."); if
			 * (Q.isZero()) { throw new RuntimeException("LOGIC ERROR!"); } //
			 */
			/*
			 * System.out.println("Benchmarking BNField12:"); f = new BNField12(bn, _2);
			 * elapsed = -System.currentTimeMillis(); for (int t = 0; t < BM; t++) { f =
			 * f.exp(k); } elapsed += System.currentTimeMillis();
			 * System.out.println("Elapsed time: " + (float)elapsed/BM + " ms."); //
			 */
			/*
			 * System.out.println("Benchmarking Tate pairing:"); f = pair.Fp12_0; elapsed =
			 * -System.currentTimeMillis(); for (int t = 0; t < BM; t++) { f =
			 * pair.tate(P,Q); } elapsed += System.currentTimeMillis();
			 * System.out.println("Elapsed time: " + (float)elapsed/BM + " ms.");
			 * //System.out.println("f = " + f); //
			 */
			/*
			 * System.out.println("Benchmarking eta pairing:"); f = pair.Fp12_0; elapsed =
			 * -System.currentTimeMillis(); for (int t = 0; t < BM; t++) { f =
			 * pair.eta(P,Q); } elapsed += System.currentTimeMillis();
			 * System.out.println("Elapsed time: " + (float)elapsed/BM + " ms.");
			 * //System.out.println("f = " + f); //
			 */
			/*
			 * System.out.println("Benchmarking ate pairing:"); f = pair.Fp12_0; elapsed =
			 * -System.currentTimeMillis(); for (int t = 0; t < BM; t++) { f = pair.ate(Q,
			 * P); } elapsed += System.currentTimeMillis();
			 * System.out.println("Elapsed time: " + (float)elapsed/BM + " ms.");
			 * //System.out.println("f = " + f); //
			 */
			/*
			 * System.out.println("Benchmarking optimal pairing:"); f = pair.Fp12_0; elapsed
			 * = -System.currentTimeMillis(); for (int t = 0; t < BM; t++) { f = pair.opt(Q,
			 * P); } elapsed += System.currentTimeMillis();
			 * System.out.println("Elapsed time: " + (float)elapsed/BM + " ms.");
			 * //System.out.println("f = " + f); //
			 */
			/*
			 * System.out.println("Benchmarking private RSA-" + 12*bn.p.bitLength());
			 * BigInteger p = BigInteger.probablePrime(6*bn.p.bitLength(), rnd); BigInteger
			 * q = BigInteger.probablePrime(6*bn.p.bitLength(), rnd); BigInteger u =
			 * q.modInverse(p); BigInteger n = p.multiply(q); BigInteger phi =
			 * p.subtract(_1).multiply(q.subtract(_1)); BigInteger e =
			 * BigInteger.valueOf(65537L); BigInteger d = e.modInverse(phi); BigInteger m =
			 * new BigInteger(12*bn.p.bitLength(), rnd).mod(n); elapsed =
			 * -System.currentTimeMillis(); for (int t = 0; t < BM; t++) { //m = m.modPow(d,
			 * n); // chinese remainder theorem: BigInteger mp = m.modPow(d, p); BigInteger
			 * mq = m.modPow(d, q); m =
			 * mp.subtract(mq).multiply(u).mod(p).multiply(q).add(mq); } elapsed +=
			 * System.currentTimeMillis(); System.out.println("Elapsed time: " +
			 * (float)elapsed/BM + " ms."); //
			 */
			/*
			 * //P = P.randomize(rnd); //Q = Q.randomize(rnd);
			 * System.out.println("Optimal pairing statistics:"); BNPairing.reset(); f =
			 * pair.opt(Q, P); long addcount = BNPairing.getadd(); long mulcount =
			 * BNPairing.getmul(); long sqrcount = BNPairing.getsqr(); long modcount =
			 * BNPairing.getmod(); long fpmcount = BNPairing.getfpm();
			 * System.out.println("Fp  add/sub  = " + addcount);
			 * System.out.println("Fp  mul      = " + fpmcount);
			 * System.out.println("Fp2 mul      = " + mulcount);
			 * System.out.println("Fp2 sqr      = " + sqrcount);
			 * System.out.println("Fp2 mod      = " + modcount);
			 * System.out.println("equiv Fp mul = " + (fpmcount + addcount/17 +
			 * 27*modcount/10)); //
			 */

			// *
			System.out.println("---------------------------------");
			System.out.println("Testing SW Enconding (Hash) to BN");

			//BigInteger t = bn.randomBigInteger(BNParams.validBitsRange[i], rnd).mod(bn.p);
			//BNPoint hashBN;
			//hashBN = bn.SWEncBN(t, bn, E, rnd);
			// */
		}

		main0(args);
	}

	public static void main0(String[] args) throws IOException, NoSuchAlgorithmException {
		benchmarks(100, 158);
	}
}
