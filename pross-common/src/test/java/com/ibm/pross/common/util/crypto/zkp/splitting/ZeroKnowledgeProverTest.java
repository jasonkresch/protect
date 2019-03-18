package com.ibm.pross.common.util.crypto.zkp.splitting;

import static org.junit.Assert.fail;

import java.math.BigInteger;

import org.junit.Assert;
import org.junit.Test;

import com.ibm.pross.common.config.CommonConfiguration;
import com.ibm.pross.common.util.RandomNumberGenerator;
import com.ibm.pross.common.util.crypto.ecc.EcCurve;
import com.ibm.pross.common.util.crypto.ecc.EcPoint;

public class ZeroKnowledgeProverTest {

	@Test
	public void testCreateProof() {
		fail("Not yet implemented");
	}

	@Test
	public void testCreateVerifyProof() {

		final EcCurve curve = CommonConfiguration.CURVE;
		final EcPoint g = CommonConfiguration.g;
		final EcPoint h = CommonConfiguration.h;

		final BigInteger a0 = RandomNumberGenerator.generateRandomInteger(curve.getR());
		final BigInteger b0 = RandomNumberGenerator.generateRandomInteger(curve.getR());
		final EcPoint A0 = curve.multiply(g, a0);
		final EcPoint B0 = curve.multiply(h, b0);
		final EcPoint C0 = curve.addPoints(A0, B0);

		final ZeroKnowledgeProof zkp = ZeroKnowledgeProver.createProof(a0, b0);
		System.out.println(zkp);

		boolean valid = ZeroKnowledgeProver.verifyProof(C0, zkp);
		System.out.println("Verified proof: " + valid);

		Assert.assertTrue(valid);
	}


	@Test
	public void testProofPerformance() {
		
		final EcCurve curve = CommonConfiguration.CURVE;

		final BigInteger a0 = RandomNumberGenerator.generateRandomInteger(curve.getR());
		final BigInteger b0 = RandomNumberGenerator.generateRandomInteger(curve.getR());
		
		
		// Warm up
		ZeroKnowledgeProof zkp = null;
		for (int i = 0; i < 20; i++)
		{
			zkp = ZeroKnowledgeProver.createProof(a0, b0);
		}
		
		int length = (zkp.getA0().getX().toByteArray().length + 1) + (zkp.getB0().getX().toByteArray().length + 1) + zkp.getC().toByteArray().length + zkp.getSa().toByteArray().length + zkp.getSb().toByteArray().length;
		System.out.println("size: " + length);
		
		// Do test
		long timeNs = 0;
		final int iterations = 1000;
		for (int i = 0; i < iterations; i++)
		{
			final BigInteger a = RandomNumberGenerator.generateRandomInteger(curve.getR());
			final BigInteger b = RandomNumberGenerator.generateRandomInteger(curve.getR());
			final long start = System.nanoTime();
			ZeroKnowledgeProver.createProof(a, b);
			final long end = System.nanoTime();
			timeNs += (end - start);
		}
		
		System.out.println("Total time (ms): " + timeNs / (((long)iterations) * 1_000_000.0));
	}
	


	@Test
	public void testVerifyPerformance() {
		
		final EcCurve curve = CommonConfiguration.CURVE;
		final EcPoint g = CommonConfiguration.g;
		final EcPoint h = CommonConfiguration.h;

		final BigInteger a0 = RandomNumberGenerator.generateRandomInteger(curve.getR());
		final BigInteger b0 = RandomNumberGenerator.generateRandomInteger(curve.getR());
		
		// Warm up
		ZeroKnowledgeProof zkp = null;
		for (int i = 0; i < 20; i++)
		{
			zkp = ZeroKnowledgeProver.createProof(a0, b0);
		}
		int length = (zkp.getA0().getX().toByteArray().length + 1) + (zkp.getB0().getX().toByteArray().length + 1) + zkp.getC().toByteArray().length + zkp.getSa().toByteArray().length + zkp.getSb().toByteArray().length;
		System.out.println("size: " + length);
		
		// Do test
		long timeNs = 0;
		final int iterations = 1000;
		for (int i = 0; i < iterations; i++)
		{
			final BigInteger a = RandomNumberGenerator.generateRandomInteger(curve.getR());
			final BigInteger b = RandomNumberGenerator.generateRandomInteger(curve.getR());
			final EcPoint A = curve.multiply(g, a);
			final EcPoint B = curve.multiply(h, b);
			final EcPoint C = curve.addPoints(A, B);
			zkp = ZeroKnowledgeProver.createProof(a, b);
			final long start = System.nanoTime();			
			ZeroKnowledgeProver.verifyProof(C, zkp);
			final long end = System.nanoTime();
			timeNs += (end - start);
		}
		
		System.out.println("Total time (ms): " + timeNs / (((long)iterations) * 1_000_000.0));
	}
	

	
}
