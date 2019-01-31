package com.ibm.pross.common.util.crypto.zkp.splitting;

import static org.junit.Assert.fail;

import java.math.BigInteger;

import org.junit.Assert;
import org.junit.Test;

import com.ibm.pross.common.CommonConfiguration;
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

}
