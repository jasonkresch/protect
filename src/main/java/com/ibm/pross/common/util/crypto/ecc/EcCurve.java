/*
 * Copyright (c) IBM Corporation 2018. All Rights Reserved.
 * Project name: pross
 * This project is licensed under the MIT License, see LICENSE.
 */

package com.ibm.pross.common.util.crypto.ecc;

import java.math.BigInteger;

/**
 * Standard supported named curves.
 * 
 * NIST defined curves found in:
 * http://csrc.nist.gov/groups/ST/toolkit/documents/dss/NISTReCur.pdf
 * 
 * Certicom defined secp256k1 found in: http://www.secg.org/sec2-v2.pdf
 * 
 * Note that this class only supports Weierstrass parameters. That is, curves
 * which are defined as: y^2 = x^3 + ax + b
 * 
 * @author jresch
 */
public interface EcCurve {

	// Approximate security ~= 128 bits
	// a.k.a. NIST P-256 a.k.a. prime256v1
	public static final EcCurve secp256r1 = new EcCurveImpl(
			new BigInteger("115792089210356248762697446949407573530086143415290314195533631308867097853948"), // a
			new BigInteger("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b", 16), // b
			new BigInteger("115792089210356248762697446949407573530086143415290314195533631308867097853951"), // p
			new BigInteger("115792089210356248762697446949407573529996955224135760342422259061068512044369"), // r
			new BigInteger("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296", 16), // Gx
			new BigInteger("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5", 16)); // Gy

	// Approximate security ~= 192 bits
	// a.k.a. NIST P-384
	public static final EcCurve secp384r1 = new EcCurveImpl(new BigInteger(
			"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFC", 16), // a
			new BigInteger(
					"B3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF",
					16), // b
			new BigInteger(
					"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF",
					16), // p
			new BigInteger(
					"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973",
					16), // r
			new BigInteger(
					"AA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7",
					16), // Gx
			new BigInteger(
					"3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F",
					16)); // Gy

	// Approximate security ~= 260 bits
	// a.k.a. NIST P-521
	public static final EcCurve secp521r1 = new EcCurveImpl(new BigInteger(
			"6864797660130609714981900799081393217269435300143305409394463459185543183397656052122559640661454554977296311391480858037121987999716643812574028291115057148"), // a
			new BigInteger(
					"051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00",
					16), // b
			new BigInteger(
					"6864797660130609714981900799081393217269435300143305409394463459185543183397656052122559640661454554977296311391480858037121987999716643812574028291115057151"), // p
			new BigInteger(
					"6864797660130609714981900799081393217269435300143305409394463459185543183397655394245057746333217197532963996371363321113864768612440380340372808892707005449"), // r
			new BigInteger(
					"c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66",
					16), // Gx
			new BigInteger(
					"11839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650",
					16)); // Gy

	public static final BigInteger TWO = BigInteger.valueOf(2);
	public static final BigInteger THREE = BigInteger.valueOf(3);



	/**
	 * Add two points together and return the sum
	 * 
	 * @param p
	 * @param q
	 * @return
	 */
	public EcPoint addPoints(EcPoint p, EcPoint q);

	/**
	 * Double a point's value (multiply by 2)
	 * 
	 * @param p
	 * @return
	 */
	public EcPoint pointDouble(EcPoint p);

	/**
	 * Multiply a point on this curve by a constant
	 * 
	 * @param p
	 * @param n
	 * @return
	 */
	public EcPoint multiply(final EcPoint p, BigInteger n);

	/**
	 * Evaluates the elliptic curve equation given x
	 * 
	 * @param x
	 * @return
	 */
	public BigInteger computeYSquared(BigInteger x);

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
	public boolean isPointOnCurve(EcPoint q);

	/**
	 * Return other solution for y^2
	 * 
	 * @param point
	 * @return
	 */
	public EcPoint reflectPoint(final EcPoint point);

	/**
	 * Returns the first co-efficient (of the x^1 term)
	 * @return
	 */
	public BigInteger getA();

	/**
	 * Returns the second coefficient (of the x^0 term)
	 * 
	 * @return
	 */
	public BigInteger getB();

	/**
	 * Returns the prime that defines the field
	 * @return
	 */
	public BigInteger getP();

	/**
	 * Returns the order of the curve (how many unique points exist)
	 * @return
	 */
	public BigInteger getR();

	/**
	 * Returns the generator for this curve
	 * @return
	 */
	public EcPoint getG();

	/**
	 * Returns the OID for this curve
	 * @return
	 */
	public String getOid();

	/**
	 * Returns the name for this curve
	 * @return
	 */
	public String getName();

	/**
	 * Returns a constant-time point hashing algorithm for this curve
	 * @return
	 */
	public PointHasher getPointHasher();

}
