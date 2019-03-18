package com.ibm.pross.server.pvss.exponent;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;

import com.ibm.pross.common.config.CommonConfiguration;
import com.ibm.pross.common.util.RandomNumberGenerator;
import com.ibm.pross.common.util.crypto.ecc.EcCurve;
import com.ibm.pross.common.util.crypto.ecc.EcPoint;

public class DLEQ {

	private final EcPoint g1;
	private final EcPoint g2;
	
	private final EcPoint h1;
	private final EcPoint h2;
	
	private final EcCurve curve;
	
	private final BigInteger x;
	
	// For proving
	private final BigInteger r;
	private final EcPoint a1;
	private final EcPoint a2;
	
	public DLEQ(final EcPoint g1, final EcPoint g2, final EcCurve curve, final BigInteger x)
	{
		this.x = x;
		
		this.g1 = g1;
		this.g2 = g2;
		
		this.curve = curve;
		
		this.h1 = curve.multiply(g1, x);
		this.h2 = curve.multiply(g2, x);
		
		this.r = RandomNumberGenerator.generateRandomInteger(curve.getR());
		this.a1 = curve.multiply(g1, r);
		this.a2 = curve.multiply(g2, r);
	}
	
	final EcPoint getH1()
	{
		return this.h1;
	}
	
	final EcPoint getH2()
	{
		return this.h2;
	}
	
	final EcPoint getA1()
	{
		return this.a1;
	}
	
	final EcPoint getA2()
	{
		return this.a2;
	}
	
	final BigInteger getS(final BigInteger challenge)
	{
		return (this.r.subtract(challenge.multiply(x).mod(curve.getR()))).mod(curve.getR());
	}
	
	
	public static void main(String args[])
	{
		final EcCurve curve = CommonConfiguration.CURVE;
		final EcPoint G1 = curve.getG();
		final EcPoint G2 = curve.getPointHasher().hashToCurve("nothing up my sleeve".getBytes(StandardCharsets.UTF_8));

		final BigInteger x = RandomNumberGenerator.generateRandomInteger(curve.getR());
		final DLEQ dleq = new DLEQ(G1, G2, curve, x);
		
		// Verify result
		final EcPoint H1 = dleq.getH1();
		final EcPoint H2 = dleq.getH2();
		final EcPoint a1 = dleq.getA1();
		final EcPoint a2 = dleq.getA2();
		final BigInteger c = RandomNumberGenerator.generateRandomInteger(curve.getR());
		final BigInteger s = dleq.getS(c);
		
		// Check first point
		final EcPoint G1s = curve.multiply(G1, s);
		final EcPoint H1c = curve.multiply(H1, c);
		final EcPoint G1sH1c = curve.addPoints(G1s, H1c);
		if (!G1sH1c.equals(a1))
		{
			System.err.println("Proof failed!");
			return;
		}
		
		// Check second point
		final EcPoint G2s = curve.multiply(G2, s);
		final EcPoint H2c = curve.multiply(H2, c);
		final EcPoint G2sH2c = curve.addPoints(G2s, H2c);
		if (!G2sH2c.equals(a2))
		{
			System.err.println("Proof failed!");
			return;
		}
		
		System.out.println("Proof passed!");
	}
	
}
