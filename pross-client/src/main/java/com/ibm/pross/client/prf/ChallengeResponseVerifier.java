/*
 * Copyright (c) IBM Corporation 2018. All Rights Reserved.
 * Project name: pross
 * This project is licensed under the MIT License, see LICENSE.
 */

package com.ibm.pross.client.prf;

import java.math.BigInteger;

import com.ibm.pross.common.util.crypto.ecc.EcCurve;
import com.ibm.pross.common.util.crypto.ecc.EcPoint;

/**
 * Generates challenges and verifies responses. This is loosely based on Chaum's
 * undeniable signatures.
 * 
 * @see https://link.springer.com/content/pdf/10.1007/3-540-46877-3_41.pdf
 * 
 * @author jresch
 */
public class ChallengeResponseVerifier {

	/**
	 * Generates a challenge based on the keyIdPoint, and random challenge
	 * factors
	 * 
	 * @param keyIdPoint
	 * @param challengeFactorV
	 * @param challengeFactorW
	 * @param curve
	 * @return
	 */
	public static EcPoint generateChallenge(final EcPoint keyIdPoint, final BigInteger challengeFactorV,
			final BigInteger challengeFactorW, final EcCurve curve) {

		// Compute challenge: (Gw+Dv)
		final EcPoint Gw = curve.multiply(curve.getG(), challengeFactorW);
		final EcPoint Dv = curve.multiply(keyIdPoint, challengeFactorV);

		return curve.addPoints(Gw, Dv);
	}

	/**
	 * Verifies the validity of the server's response to the challenge
	 * 
	 * @param response
	 * @param publicKey
	 * @param challengeFactorV
	 * @param challengeFactorW
	 * @param curve
	 * @param derivedResult
	 * @return
	 */
	public static boolean isResponseValid(final EcPoint response, final EcPoint publicKey,
			final BigInteger challengeFactorV, final BigInteger challengeFactorW, final EcCurve curve,
			final EcPoint derivedResult) {

		// Response point should be (Gw+Dv)k -- if computed correctly
		// publicKey is Gk

		// Compute inverse of v and first part of calculation
		final BigInteger inverseV = challengeFactorV.modInverse(curve.getR());

		// Compute first part of response verification, part_1 = (Gw+Dv)k*(1/v)
		// = (Gwk/v + Dk)
		final EcPoint part1 = curve.multiply(response, inverseV);

		// Compute second part of response verification, part_2 = Gk*(-w/v)
		final EcPoint part2 = curve.multiply(publicKey, curve.getR().subtract(challengeFactorW).multiply(inverseV));

		// Sum parts and compare to recovered point Compute final result and
		// check if it matches expectations, if server used correct "k" it will.
		// test_result = (Gwk/v + Dk) + Gk*(-w/v) = (Gwk/v + -Gwk/v) + Dk = (0)
		// + Dk = Dk = recovered_point
		final EcPoint testResult = curve.addPoints(part1, part2);

		if (testResult.getX().equals(derivedResult.getX())) {
			return true;
		} else {
			// We need to try the negative y solution in case the first doesn't
			// work
			final EcPoint altPart1 = curve.multiply(curve.reflectPoint(response), inverseV);
			final EcPoint altTestResult = curve.addPoints(altPart1, part2);

			return altTestResult.getX().equals(derivedResult.getX());
		}
	}

}
