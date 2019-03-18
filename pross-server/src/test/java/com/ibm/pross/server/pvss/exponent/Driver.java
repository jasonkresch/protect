package com.ibm.pross.server.pvss.exponent;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

import com.ibm.pross.common.DerivationResult;
import com.ibm.pross.common.config.CommonConfiguration;
import com.ibm.pross.common.util.crypto.ecc.EcCurve;
import com.ibm.pross.common.util.crypto.ecc.EcPoint;
import com.ibm.pross.common.util.shamir.Polynomials;
import com.ibm.pross.common.util.shamir.Shamir;
import com.ibm.pross.common.util.shamir.ShamirShare;

public class Driver {

	public static void main(String[] args) {

		// Define Generators

		// Group Constants
		final EcCurve curve = CommonConfiguration.CURVE;
		final EcPoint G1 = curve.getPointHasher().hashToCurve(new byte[] { 0x01 });
		final EcPoint G2 = curve.getPointHasher().hashToCurve(new byte[] { 0x02 });
		final EcPoint H1 = curve.getPointHasher().hashToCurve(new byte[] { 0x03 });
		final EcPoint H2 = curve.getPointHasher().hashToCurve(new byte[] { 0x04 });

		// Set n, t
		final int n = 5;
		final int t = 3;

		// Generate key pairs for each participant
		final KeyPair[] keyPairs = new KeyPair[n];
		for (int i = 0; i < n; i++) {
			keyPairs[i] = KeyPair.generateKeyPair(G1, H1, curve);
		}

		// Generate two polynomials
		final BigInteger[] f = Shamir.generateCoefficients(t);
		final BigInteger[] g = Shamir.generateCoefficients(t);

		// Define the secret: S = G1*f(0) + H1*g(0)
		final BigInteger s1 = f[0];
		final BigInteger s2 = g[0];
		final EcPoint S = curve.addPoints(curve.multiply(G1, s1), curve.multiply(H1, s2));

		// Create commitments
		final EcPoint[] commitments = new EcPoint[t];
		for (int j = 0; j < t; j++) {
			commitments[j] = curve.addPoints(curve.multiply(G2, f[j]), curve.multiply(H2, g[j]));
		}

		// Create encrypted shares
		final EcPoint encryptedShares[] = new EcPoint[n];
		for (int i = 0; i < n; i++) {
			final EcPoint Y1 = keyPairs[i].getPublicKey().getY1();
			final EcPoint Y2 = keyPairs[i].getPublicKey().getY2();

			final ShamirShare fi = Polynomials.evaluatePolynomial(f, BigInteger.valueOf(i + 1), curve.getR());
			final ShamirShare gi = Polynomials.evaluatePolynomial(g, BigInteger.valueOf(i + 1), curve.getR());

			// Share = y1*f(i) + y2*g(i)
			encryptedShares[i] = curve.addPoints(curve.multiply(Y1, fi.getY()), curve.multiply(Y2, gi.getY()));
		}

		// Create Xis
		final EcPoint Xis[] = new EcPoint[n];
		for (int i = 0; i < n; i++) {
			Xis[i] = EcPoint.pointAtInfinity;
			for (int j = 0; j < t; j++) {
				Xis[i] = curve.addPoints(Xis[i], curve.multiply(commitments[j], BigInteger.valueOf(i + 1).pow(j)));
			}
		}

		// Create shares (we don't publish these)
		final EcPoint shares[] = new EcPoint[n];
		for (int i = 0; i < n; i++) {
			final ShamirShare fi = Polynomials.evaluatePolynomial(f, BigInteger.valueOf(i + 1), curve.getR());
			final ShamirShare gi = Polynomials.evaluatePolynomial(g, BigInteger.valueOf(i + 1), curve.getR());
			shares[i] = curve.addPoints(curve.multiply(G1, fi.getY()), curve.multiply(H1, gi.getY()));
		}

		// Create proofs
		final Proof proofs[] = new Proof[n];
		for (int i = 0; i < n; i++) {

			// Shares
			final ShamirShare fi = Polynomials.evaluatePolynomial(f, BigInteger.valueOf(i + 1), curve.getR());
			final ShamirShare gi = Polynomials.evaluatePolynomial(g, BigInteger.valueOf(i + 1), curve.getR());

			// Public Keys
			final EcPoint Y1 = keyPairs[i].getPublicKey().getY1();
			final EcPoint Y2 = keyPairs[i].getPublicKey().getY2();

			proofs[i] = Prover.sign(Xis[i], encryptedShares[i], G2, H2, Y1, Y2, fi.getY(), gi.getY(), curve);
		}

		// Publish (commitments, encrypted shares, and proofs)

		// Verify publicly
		for (int i = 0; i < n; i++) {
			System.out.println("Proof #" + i + ": " + proofs[i].isValid());
			// TODO: Compare values within proof against what was published
		}

		// Decrypted shares, verify privately
		List<DerivationResult> results = new ArrayList<>(n);
		for (int i = 0; i < n; i++) {
			final BigInteger x = keyPairs[i].getPrivateKey().getX();

			// Share = Yi/x
			final EcPoint decryptedShare = curve.multiply(encryptedShares[i], x.modInverse(curve.getR()));
			
			System.out.println("Share[" + i + "] Decrypted properly: " + decryptedShare.equals(shares[i]));
			results.add(new DerivationResult(BigInteger.valueOf(i + 1), decryptedShare));
		}

		// Recover Secret
		final EcPoint recoveredShare = Polynomials.interpolateExponents(results, t, 0);
		System.out.println("Recovered share: " + recoveredShare.equals(S));
	}

}
