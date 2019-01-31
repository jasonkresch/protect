package com.ibm.pross.server.pvss.exponent;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import com.ibm.pross.common.CommonConfiguration;
import com.ibm.pross.common.util.RandomNumberGenerator;
import com.ibm.pross.common.util.crypto.ecc.EcCurve;
import com.ibm.pross.common.util.crypto.ecc.EcPoint;
import com.ibm.pross.common.util.serialization.Parse;

public class Prover {
	
	public static final String HASH_ALGORITHM = "SHA-512";
	
	public static Proof sign(final BigInteger x1, final BigInteger x2, final EcPoint G1, final EcPoint G2, final EcPoint H1,
			final EcPoint H2, final EcCurve curve) {
		
		// Compute X
		final EcPoint G1x1 = curve.multiply(G1, x1);
		final EcPoint G2x2 = curve.multiply(G2, x2);
		final EcPoint X = curve.addPoints(G1x1, G2x2);
		
		// Compute Y
		final EcPoint H1x1 = curve.multiply(H1, x1);
		final EcPoint H2x2 = curve.multiply(H2, x2);
		final EcPoint Y = curve.addPoints(H1x1, H2x2);
		
		return sign(X, Y, G1, G2, H1, H2, x1, x2, curve);
	}
	
	public static Proof sign(final EcPoint X, final EcPoint Y, final EcPoint G1, final EcPoint G2, final EcPoint H1,
			final EcPoint H2, final BigInteger x1, final BigInteger x2, final EcCurve curve) {

		// Generate two random numbers
		final BigInteger s = RandomNumberGenerator.generateRandomInteger(curve.getR());
		final BigInteger t = RandomNumberGenerator.generateRandomInteger(curve.getR());
		
		// Compute XPrime
		final EcPoint G1s = curve.multiply(G1, s);
		final EcPoint G2t = curve.multiply(G2, t);
		final EcPoint XPrime = curve.addPoints(G1s, G2t);
		
		// Compute YPrime
		final EcPoint H1s = curve.multiply(H1, s);
		final EcPoint H2t = curve.multiply(H2, t);
		final EcPoint YPrime = curve.addPoints(H1s, H2t);
		
		// Compute c
		final byte[] input = Parse.concatenate(G1, G2, H1, H2, X, XPrime, Y, YPrime);
		final MessageDigest digest;
		try {
			digest = MessageDigest.getInstance(HASH_ALGORITHM);
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException("Should not happen");
		}
		final BigInteger c = new BigInteger(1, digest.digest(input)).mod(curve.getR());
		
		// Compute r1 and r2
		final BigInteger r1 = ((c.multiply(x1)).add(s)).mod(curve.getR());
		final BigInteger r2 = ((c.multiply(x2)).add(t)).mod(curve.getR());
		
		return new Proof(G1, G2, H1, H2, X, XPrime, Y, YPrime, r1, r2, curve);
	}

	public static void main(String args[])
	{
		final EcCurve curve = CommonConfiguration.CURVE;
		final EcPoint G1 = curve.getPointHasher().hashToCurve("G1".getBytes(StandardCharsets.UTF_8));
		final EcPoint G2 = curve.getPointHasher().hashToCurve("G2".getBytes(StandardCharsets.UTF_8));
		final EcPoint H1 = curve.getPointHasher().hashToCurve("H1".getBytes(StandardCharsets.UTF_8));
		final EcPoint H2 = curve.getPointHasher().hashToCurve("H2".getBytes(StandardCharsets.UTF_8));

		final BigInteger x1 = RandomNumberGenerator.generateRandomInteger(curve.getR());
		final BigInteger x2 = RandomNumberGenerator.generateRandomInteger(curve.getR());
		
		final Proof proof = sign(x1, x2, G1, G2, H1, H2, curve);
		System.out.println(proof.isValid());
	}
	
}
