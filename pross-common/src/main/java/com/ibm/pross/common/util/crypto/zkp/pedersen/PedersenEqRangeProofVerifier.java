package com.ibm.pross.common.util.crypto.zkp.pedersen;

import java.math.BigInteger;

import com.ibm.pross.common.config.CommonConfiguration;
import com.ibm.pross.common.util.Exponentiation;
import com.ibm.pross.common.util.crypto.ecc.EcCurve;
import com.ibm.pross.common.util.crypto.ecc.EcPoint;
import com.ibm.pross.common.util.crypto.paillier.PaillierCipher;
import com.ibm.pross.common.util.crypto.paillier.PaillierPublicKey;

public class PedersenEqRangeProofVerifier {

	// Group Constants
	public static final EcCurve curve = CommonConfiguration.CURVE;
	public static final EcPoint g = CommonConfiguration.g;
	public static final EcPoint h = CommonConfiguration.h;

	public static boolean isValid(final PedersenEqRangeProof proof, final BigInteger Ea, final BigInteger Eb,
			final EcPoint S, final PaillierPublicKey publicKey) {

		// Get fields of the proof
		final BigInteger Ealpha = proof.getEalpha();
		final BigInteger Ebeta = proof.getEbeta();
		final EcPoint S1 = proof.getS1();
		final BigInteger z1 = proof.getZ1();
		final BigInteger z2 = proof.getZ2();
		final BigInteger e1 = proof.getE1();
		final BigInteger e2 = proof.getE2();

		// Step 1: Recompute c = H(Ealpha, Ebeta, S1, Ea, Eb, S)
		final BigInteger c = PedersenEqRangeProofGenerator.hashParameters(Ealpha, Ebeta, S1, Ea, Eb, S);

		// Step 2: Enc(z1, e1) = Ea^c * Eα
		final BigInteger nSquared = publicKey.getNSquared();
		final BigInteger enc1 = PaillierCipher.encrypt(publicKey, z1, e1);
		final BigInteger product1 = Exponentiation.modPow(Ea, c, nSquared).multiply(Ealpha).mod(nSquared);
		if (!enc1.equals(product1)) {
			return false;
		}
		
		// Step 3: Enc(z2, e2) = Eb^c * Eβ
		final BigInteger enc2 = PaillierCipher.encrypt(publicKey, z2, e2);
		final BigInteger product2 = Exponentiation.modPow(Eb, c, nSquared).multiply(Ebeta).mod(nSquared);
		if (!enc2.equals(product2)) {
			return false;
		}

		// Step 4: Check that (g^z1 * h^z2) = (S^c * S1)
		final EcPoint lhs = curve.addPoints(curve.multiply(g, z1), curve.multiply(h, z2));
		final EcPoint rhs = curve.addPoints(curve.multiply(S, c), S1);
		if (!lhs.equals(rhs)) {
			return false;
		}

		// All checks passed
		return true;
	}

}
