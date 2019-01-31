package com.ibm.pross.server.pvss.exponent;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import com.ibm.pross.common.util.crypto.ecc.EcCurve;
import com.ibm.pross.common.util.crypto.ecc.EcPoint;
import com.ibm.pross.common.util.serialization.Parse;

public class Proof {

	public static final String HASH_ALGORITHM = "SHA-512";
	
	final EcPoint G1;
	final EcPoint G2;
	final EcPoint H1;
	final EcPoint H2;
	final EcPoint X;
	final EcPoint XPrime;
	final EcPoint Y;
	final EcPoint YPrime;
	final BigInteger r1;
	final BigInteger r2;
	final EcCurve curve;
	
	public Proof(final EcPoint G1, final EcPoint G2, final EcPoint H1, final EcPoint H2, final EcPoint X,
			final EcPoint XPrime, final EcPoint Y, final EcPoint YPrime, final BigInteger r1, final BigInteger r2,
			final EcCurve curve) {
		this.G1 = G1;
		this.G2 = G2;
		this.H1 = H1;
		this.H2 = H2;
		this.X = X;
		this.XPrime = XPrime;
		this.Y = Y;
		this.YPrime = YPrime;
		this.r1 = r1;
		this.r2 = r2;
		this.curve = curve;
	}
	
	public boolean isValid()
	{
		// Compute c
		final byte[] input = Parse.concatenate(G1, G2, H1, H2, X, XPrime, Y, YPrime);
		final MessageDigest digest;
		try {
			digest = MessageDigest.getInstance(HASH_ALGORITHM);
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException("Should not happen");
		}
		final BigInteger c = new BigInteger(1, digest.digest(input)).mod(curve.getR());
		
		// Compute G1r1G2r2
		final EcPoint G1r1 = curve.multiply(G1, r1);
		final EcPoint G2r2 = curve.multiply(G2, r2);
		final EcPoint G1r1G2r2 = curve.addPoints(G1r1, G2r2);
		
		// Compare to XcXPrime
		final EcPoint XcXPrime = curve.addPoints(curve.multiply(X, c), XPrime);
		if (!G1r1G2r2.equals(XcXPrime)) {
			return false;
		}
		
		// Compute H1r1H2r2
		final EcPoint H1r1 = curve.multiply(H1, r1);
		final EcPoint H2r2 = curve.multiply(H2, r2);
		final EcPoint H1r1H2r2 = curve.addPoints(H1r1, H2r2);
		
		// Compare to YcYPrime
		final EcPoint YcYPrime = curve.addPoints(curve.multiply(Y, c), YPrime);
		if (!H1r1H2r2.equals(YcYPrime)) {
			return false;
		}
		
		return true;
	}

}
