package com.ibm.pross.common.util.crypto.zkp.feldman;

import java.math.BigInteger;

import com.ibm.pross.common.config.CommonConfiguration;
import com.ibm.pross.common.util.Exponentiation;
import com.ibm.pross.common.util.crypto.ecc.EcCurve;
import com.ibm.pross.common.util.crypto.ecc.EcPoint;
import com.ibm.pross.common.util.crypto.paillier.PaillierCipher;
import com.ibm.pross.common.util.crypto.paillier.PaillierPublicKey;

public class FeldmanEqRangeProofVerifier {

	// Group Constants
	public static final EcCurve curve = CommonConfiguration.CURVE;
	public static final EcPoint g = CommonConfiguration.g;
	public static final EcPoint h = CommonConfiguration.h;

	public static boolean isValid(final FeldmanEqRangeProof proof, final BigInteger E, final EcPoint S,
			final PaillierPublicKey publicKey) {

		// Get fields of the proof
		final BigInteger E1 = proof.getE1();
		final EcPoint S1 = proof.getS1();
		final BigInteger z = proof.getZ();
		final BigInteger z1 = proof.getZ1();
		final BigInteger z2 = proof.getZ2();

		// Step 0: Recompute c = H(E1, S1, E, S)
		final BigInteger c = FeldmanEqRangeProofGenerator.hashParameters(E1, S1, E, S);

		// Step 1: Validate z
		if ((z.compareTo(FeldmanEqRangeProofGenerator.Z) > 0) || (z.signum() == -1)) {
			return false; // z is in bad range
		}

		// Step 2: Enc(z1, z2) = E^c * E1
		final BigInteger nSquared = publicKey.getNSquared();
		final BigInteger enc = PaillierCipher.encrypt(publicKey, z, z1);
		final BigInteger product = Exponentiation.modPow(E, c, nSquared).multiply(E1).mod(nSquared);
		if (!enc.equals(product)) {
			return false;
		}

		// Step 3: Check that (g^z * h^z2) = (S^c * S1)
		final EcPoint lhs = curve.addPoints(curve.multiply(g, z), curve.multiply(h, z2));
		final EcPoint rhs = curve.addPoints(curve.multiply(S, c), S1);
		if (!lhs.equals(rhs)) {
			return false;
		}

		// All checks passed
		return true;
	}

}
