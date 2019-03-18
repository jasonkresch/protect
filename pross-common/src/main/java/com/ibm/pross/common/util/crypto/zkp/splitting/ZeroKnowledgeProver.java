package com.ibm.pross.common.util.crypto.zkp.splitting;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import com.ibm.pross.common.config.CommonConfiguration;
import com.ibm.pross.common.util.RandomNumberGenerator;
import com.ibm.pross.common.util.crypto.ecc.EcCurve;
import com.ibm.pross.common.util.crypto.ecc.EcPoint;
import com.ibm.pross.common.util.serialization.Parse;

/**
 * Creates a zero knowledge proof of two exponents a0 and b0
 * 
 * 
 */
public class ZeroKnowledgeProver {
	
	// Group Constants
	public static final EcCurve curve = CommonConfiguration.CURVE;
	public static final EcPoint g = CommonConfiguration.g;
	public static final EcPoint h = CommonConfiguration.h;
	
	public static final String HASH_ALGORITHM = CommonConfiguration.HASH_ALGORITHM;
	
	public static ZeroKnowledgeProof createProof(final BigInteger a0, final BigInteger b0)
	{
		// Calculate A0 and B0
		final EcPoint A0 = curve.multiply(g, a0);
		final EcPoint B0 = curve.multiply(h, b0);
		
		// Chose random points
		final BigInteger r1 = RandomNumberGenerator.generateRandomInteger(curve.getR());
		final BigInteger r2 = RandomNumberGenerator.generateRandomInteger(curve.getR());
		
		// Compute powers
		final EcPoint p1 = curve.multiply(g, r1);
		final EcPoint p2 = curve.multiply(h, r2);
		final EcPoint sum = curve.addPoints(p1, p2);
		
		// Compute c
		final byte[] input = Parse.concatenate(g, h, sum);
		final MessageDigest digest;
		try {
			digest = MessageDigest.getInstance(HASH_ALGORITHM);
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException("Should not happen");
		}
		final BigInteger c = new BigInteger(1, digest.digest(input)).mod(curve.getR());
		
		// Compute sa and sb
		final BigInteger sa = (r1.subtract(c.multiply(a0))).mod(curve.getR());
		final BigInteger sb = (r2.subtract(c.multiply(b0))).mod(curve.getR());
		
		return new ZeroKnowledgeProof(A0, B0, c, sa, sb);
	}
	
	/**
	 * Verifies consistency of the proof against a commitment
	 * @param C0
	 *  C0 = (g^a0 * h^b0) -- The pedersen commitment 
	 * @param proof
	 * @return
	 */
	public static boolean verifyProof(final EcPoint C0, final ZeroKnowledgeProof proof)
	{
		// Verify A0 and B0
		final EcPoint A0 = proof.getA0();
		final EcPoint B0 = proof.getB0();
		final EcPoint expectedC0 = curve.addPoints(A0, B0);
		if (!C0.equals(expectedC0))
		{
			return false;
		}
		
		// Compute V
		final EcPoint Gsa = curve.multiply(g, proof.getSa());
		final EcPoint Hsb = curve.multiply(h, proof.getSb());
		final EcPoint Cc = curve.multiply(C0, proof.getC());
		final EcPoint V = curve.addPoints(Cc, curve.addPoints(Gsa, Hsb));
		
		// Compute c
		final byte[] input = Parse.concatenate(g, h, V);
		final MessageDigest digest;
		try {
			digest = MessageDigest.getInstance(HASH_ALGORITHM);
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException("Should not happen");
		}
		final BigInteger computedC = new BigInteger(1, digest.digest(input)).mod(curve.getR());
		
		// Verify c
		return proof.getC().equals(computedC);
	}


}
