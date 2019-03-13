package com.ibm.pross.server.app;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.Signature;
import java.util.Random;
import java.util.function.Function;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import com.ibm.pross.common.config.CommonConfiguration;
import com.ibm.pross.common.util.Exponentiation;
import com.ibm.pross.common.util.RandomNumberGenerator;
import com.ibm.pross.common.util.crypto.ecc.EcCurve;
import com.ibm.pross.common.util.crypto.ecc.EcKeyGeneration;
import com.ibm.pross.common.util.crypto.ecc.EcPoint;
import com.ibm.pross.common.util.crypto.paillier.PaillierCipher;
import com.ibm.pross.common.util.crypto.paillier.PaillierKeyGenerator;
import com.ibm.pross.common.util.crypto.paillier.PaillierKeyPair;
import com.ibm.pross.common.util.crypto.zkp.pedersen.PedersenEqRangeProof;
import com.ibm.pross.common.util.crypto.zkp.pedersen.PedersenEqRangeProofGenerator;
import com.ibm.pross.common.util.crypto.zkp.pedersen.PedersenEqRangeProofVerifier;
import com.ibm.pross.common.util.crypto.zkp.splitting.ZeroKnowledgeProof;
import com.ibm.pross.common.util.crypto.zkp.splitting.ZeroKnowledgeProver;

import net.i2p.crypto.eddsa.EdDSASecurityProvider;

public class BenchmarkCli {

	// Constants
	public static final EcCurve curve = CommonConfiguration.CURVE;
	public static final EcPoint g = CommonConfiguration.g;
	public static final EcPoint h = CommonConfiguration.h;
	public static final int PAILLIER_KEY_SIZE = 2048;
	public static final int MODULUS_SIZE = 1024;
	public static final String ECDSA_SIG_ALGORITHM = CommonConfiguration.EC_SIGNATURE_ALGORITHM;
	public static final String EDDSA_SIG_ALGORITHM = CommonConfiguration.ED_SIGNATURE_ALGORITHM;

	// Modulus for mod pow test
	public static final BigInteger MODULUS = BigInteger.probablePrime(MODULUS_SIZE, new Random());
	public static final BigInteger BASE = RandomNumberGenerator.generateRandomInteger(MODULUS);
	public static final BigInteger EXPONENT = RandomNumberGenerator.generateRandomInteger(MODULUS);

	// Messages to sign or encrypt
	public static final byte[] TO_SIGN = new byte[1024];
	public static final BigInteger PLAINTEXT = RandomNumberGenerator.generateRandomInteger(PAILLIER_KEY_SIZE - 10);

	// Split Proof Params
	public static final BigInteger a = RandomNumberGenerator.generateRandomInteger(curve.getR());
	public static final BigInteger b = RandomNumberGenerator.generateRandomInteger(curve.getR());
	public static final EcPoint A = curve.multiply(g, a);
	public static final EcPoint B = curve.multiply(h, b);
	public static final EcPoint C = curve.addPoints(A, B);

	// Eq Range Proof Params
	public static final BigInteger share1 = RandomNumberGenerator.generateRandomInteger(curve.getR());
	public static final BigInteger share2 = RandomNumberGenerator.generateRandomInteger(curve.getR());
	public static final EcPoint S = curve.addPoints(curve.multiply(g, share1), curve.multiply(h, share2));
	public static final BigInteger r1;
	public static final BigInteger r2;
	public static final BigInteger Ea;
	public static final BigInteger Eb;

	// Keys used in tests
	public static final PaillierKeyPair paillierKeyPair;
	public static final KeyPair ecDsaKeyPair;
	public static final KeyPair edDsaKeyPair;

	// Signing Contexts
	public static final Signature ECDSA_SIGNER;
	public static final Signature ECDSA_VERIFIER;
	public static final Signature EDDSA_SIGNER;
	public static final Signature EDDSA_VERIFIER;

	static {

		// Add Providers
		Security.addProvider(new EdDSASecurityProvider());
		Security.addProvider(new BouncyCastleProvider());

		try {

			// Generate keys
			paillierKeyPair = (new PaillierKeyGenerator(PAILLIER_KEY_SIZE)).generate();
			ecDsaKeyPair = EcKeyGeneration.generateKeyPair();
			edDsaKeyPair = KeyPairGenerator.getInstance(EdDSASecurityProvider.PROVIDER_NAME).generateKeyPair();

			// Setup ECDSA Contexts
			ECDSA_SIGNER = Signature.getInstance(ECDSA_SIG_ALGORITHM, "BC");
			ECDSA_SIGNER.initSign(ecDsaKeyPair.getPrivate());
			ECDSA_VERIFIER = Signature.getInstance(ECDSA_SIG_ALGORITHM, "BC");
			ECDSA_VERIFIER.initVerify(ecDsaKeyPair.getPublic());

			// Setup EdDSA Contexts
			EDDSA_SIGNER = Signature.getInstance(EDDSA_SIG_ALGORITHM);
			EDDSA_SIGNER.initSign(edDsaKeyPair.getPrivate());
			EDDSA_VERIFIER = Signature.getInstance(EDDSA_SIG_ALGORITHM);
			EDDSA_VERIFIER.initVerify(edDsaKeyPair.getPublic());

		} catch (Exception e) {
			throw new RuntimeException("Failed to initialize");
		}

		// Encrypt shares for EqRangeProof
		final BigInteger n = paillierKeyPair.getPublicKey().getN();

		// Encrypt first share
		r1 = RandomNumberGenerator.generateRandomCoprimeInRange(n);
		Ea = PaillierCipher.encrypt(paillierKeyPair.getPublicKey(), share1, r1);

		// Encrypt second share
		r2 = RandomNumberGenerator.generateRandomCoprimeInRange(n);
		Eb = PaillierCipher.encrypt(paillierKeyPair.getPublicKey(), share2, r2);
	}

	private static volatile byte[] ECDSA_SIGNATURE;
	private static volatile byte[] EDDSA_SIGNATURE;
	private static volatile BigInteger CIPHERTEXT;
	private static volatile ZeroKnowledgeProof SPLIT_PROOF;
	private static volatile PedersenEqRangeProof EQ_PROOF;

	/**************************************************************************************/

	public static Void benchmarkModPow(final int iterations) {
		for (int i = 0; i < iterations; i++) {
			Exponentiation.modPow(BASE, EXPONENT, MODULUS);
		}
		return null;
	}

	public static Void benchmarkEcDsaSign(final int iterations) {
		try {
			for (int i = 0; i < iterations; i++) {
				ECDSA_SIGNER.update(TO_SIGN);
				ECDSA_SIGNATURE = ECDSA_SIGNER.sign();
			}
		} catch (Exception e) {
			throw new RuntimeException();
		}
		return null;
	}

	public static Void benchmarkEcDsaVerify(final int iterations) {
		try {
			for (int i = 0; i < iterations; i++) {
				ECDSA_VERIFIER.update(TO_SIGN);
				ECDSA_VERIFIER.verify(ECDSA_SIGNATURE);
			}
		} catch (Exception e) {
			throw new RuntimeException();
		}
		return null;
	}

	public static Void benchmarkEdDsaSign(final int iterations) {
		try {
			for (int i = 0; i < iterations; i++) {
				EDDSA_SIGNER.update(TO_SIGN);
				EDDSA_SIGNATURE = EDDSA_SIGNER.sign();
			}
		} catch (Exception e) {
			throw new RuntimeException();
		}
		return null;
	}

	public static Void benchmarkEdDsaVerify(final int iterations) {
		try {
			for (int i = 0; i < iterations; i++) {
				EDDSA_VERIFIER.update(TO_SIGN);
				EDDSA_VERIFIER.verify(EDDSA_SIGNATURE);
			}
		} catch (Exception e) {
			throw new RuntimeException();
		}
		return null;
	}

	public static Void benchmarkPaillierEncrypt(final int iterations) {
		for (int i = 0; i < iterations; i++) {
			CIPHERTEXT = PaillierCipher.encrypt(paillierKeyPair.getPublicKey(), PLAINTEXT);
		}
		return null;
	}

	public static Void benchmarkPaillierDecrypt(final int iterations) {
		for (int i = 0; i < iterations; i++) {
			PaillierCipher.decrypt(paillierKeyPair.getPrivateKey(), CIPHERTEXT);
		}
		return null;
	}

	public static Void benchmarkPedersenSplitProofGenerate(final int iterations) {
		for (int i = 0; i < iterations; i++) {
			SPLIT_PROOF = ZeroKnowledgeProver.createProof(a, b);
		}
		return null;
	}

	public static Void benchmarkPedersenSplitProofVerify(final int iterations) {
		for (int i = 0; i < iterations; i++) {
			ZeroKnowledgeProver.verifyProof(C, SPLIT_PROOF);
		}
		return null;
	}

	public static Void benchmarkPedersenEqRangeProofGenerate(final int iterations) {
		for (int i = 0; i < iterations; i++) {
			EQ_PROOF = PedersenEqRangeProofGenerator.generate(paillierKeyPair.getPublicKey(), share1, share2, r1, r2, Ea, Eb, S);
		}
		return null;
	}

	public static Void benchmarkPedersenEqRangeProofVerify(final int iterations) {
		for (int i = 0; i < iterations; i++) {
			PedersenEqRangeProofVerifier.isValid(EQ_PROOF, Ea, Eb, S, paillierKeyPair.getPublicKey());
		}
		return null;
	}

	public static void benchmarkMethod(final Function<Integer, Void> function, final String methodName,
			final int iterations) {
		// Warm up
		function.apply(iterations / 10);

		// Perform benchmark
		final long startTime = System.nanoTime();
		function.apply(iterations);
		final long endTime = System.nanoTime();
		final long totalTime = (endTime - startTime);

		final long operationsPerSecond = (long) (((double) (1_000_000_000L * iterations)) / ((double) totalTime));

		System.out.print(methodName + ": " + operationsPerSecond + "/s;  ");
	}

	public static void runAllBenchmarks() {
		// modPow (1024)
		benchmarkMethod(BenchmarkCli::benchmarkModPow, "ModPow", 100);

		// ECDSA sign
		benchmarkMethod(BenchmarkCli::benchmarkEcDsaSign, "ECDSA Sign", 300);

		// ECDSA verify
		benchmarkMethod(BenchmarkCli::benchmarkEcDsaVerify, "ECDSA Verify", 300);

		// EdDSA sign
		benchmarkMethod(BenchmarkCli::benchmarkEdDsaSign, "EdDSA Sign", 300);

		// EdDSA verify
		benchmarkMethod(BenchmarkCli::benchmarkEdDsaVerify, "EdDSA Verify", 300);

		// Paillier Encrypt (2048)
		benchmarkMethod(BenchmarkCli::benchmarkPaillierEncrypt, "Paillier Encrypt", 10);

		// Paillier Decrypt (2048)
		benchmarkMethod(BenchmarkCli::benchmarkPaillierDecrypt, "Paillier Decrypt", 10);

		// PedersenSplitProof Generate (ZeroKnowledgeProof)
		benchmarkMethod(BenchmarkCli::benchmarkPedersenSplitProofGenerate, "Split Prove", 100);

		// PedersenSplitProof Verify (ZeroKnowledgeProof)
		benchmarkMethod(BenchmarkCli::benchmarkPedersenSplitProofVerify, "Split Verify", 100);

		// PedersenEqRangeProofs Generate
		benchmarkMethod(BenchmarkCli::benchmarkPedersenEqRangeProofGenerate, "EqRange Prove", 5);

		// PedersenEqRangeProofs Verify
		benchmarkMethod(BenchmarkCli::benchmarkPedersenEqRangeProofVerify, "EqRange Verify", 5);

		System.out.println();
	}

	public static void main(final String args[]) {
		runAllBenchmarks();
	}

}
