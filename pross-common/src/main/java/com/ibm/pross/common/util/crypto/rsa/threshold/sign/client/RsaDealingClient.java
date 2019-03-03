package com.ibm.pross.common.util.crypto.rsa.threshold.sign.client;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import com.ibm.pross.common.CommonConfiguration;
import com.ibm.pross.common.util.Exponentiation;
import com.ibm.pross.common.util.Primes;
import com.ibm.pross.common.util.RandomNumberGenerator;
import com.ibm.pross.common.util.crypto.rsa.threshold.sign.exceptions.BadArgumentException;
import com.ibm.pross.common.util.crypto.rsa.threshold.sign.exceptions.BelowThresholdException;
import com.ibm.pross.common.util.crypto.rsa.threshold.sign.math.ThresholdSignatures;
import com.ibm.pross.common.util.crypto.rsa.threshold.sign.server.RsaSignatureServer;
import com.ibm.pross.common.util.crypto.rsa.threshold.sign.server.ServerPublicConfiguration;
import com.ibm.pross.common.util.shamir.Polynomials;
import com.ibm.pross.common.util.shamir.ShamirShare;

/**
 * Initializes a set of N servers such that future recovery of a secret is
 * possible through an interaction with at least a threshold number of
 * well-behaved servers together with knowledge of a password.
 * 
 * The password is neither stored, nor known by any other entity in the system,
 * and is only subject to the possibility of brute-force attack after a
 * threshold number of servers are compromised without an intervening "security
 * refresh"
 */
public class RsaDealingClient {

	// Security strength (of primes p and q)
	// (512-bits ~= 1024-bit RSA keys)
	public static final int PRIME_SIZE = 512;

	private final RsaSignatureServer[] servers;
	private final int threshold;

	public RsaDealingClient(RsaSignatureServer[] servers, int threshold) {
		this.servers = servers;
		this.threshold = threshold;
	}

	/**
	 * Create shares and initialize all servers with their secret shares and with a
	 * common configuration. The "registration threshold" is all n servers, and this
	 * method call will fail with a BelowThresholdException if registration does not
	 * succeed across the entire set of servers.
	 * 
	 * @param username
	 * @throws BadArgumentException
	 * @throws BelowThresholdException
	 * @throws NoSuchAlgorithmException 
	 * @throws InvalidKeySpecException 
	 * @throws InvalidKeyException 
	 * @throws NoSuchPaddingException 
	 * @throws BadPaddingException 
	 * @throws IllegalBlockSizeException 
	 */
	public byte[] registerWithServers(final String username, final byte[] toBeSigned)
			throws BadArgumentException, BelowThresholdException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
		int serverCount = this.servers.length;

		System.out.print("  Generating p...");
		final BigInteger pPrime = Primes.generateSophieGermainPrime(PRIME_SIZE);
		final BigInteger p = Primes.getSafePrime(pPrime);
		System.out.println(" done.");

		System.out.print("  Generating q...");
		final BigInteger qPrime = Primes.generateSophieGermainPrime(PRIME_SIZE);
		final BigInteger q = Primes.getSafePrime(qPrime);
		System.out.println(" done.");

		System.out.print("  Computing moduli...");
		final BigInteger m = pPrime.multiply(qPrime);
		final BigInteger n = p.multiply(q);
		System.out.println(" done.");

		// Public exponent (e must be greater than numServers)
		final BigInteger e = BigInteger.valueOf(65537);
		if (e.longValue() <= servers.length) {
			throw new BadArgumentException("e must be greater than the number of servers!");
		}

		// Create standard RSA Public key pair
		System.out.print("  Creating RSA keypair...");
		final RSAPublicKeySpec publicKeySpec = new RSAPublicKeySpec(n, e);
		final KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		final RSAPublicKey publicKey = (RSAPublicKey) keyFactory.generatePublic(publicKeySpec);

		// Create standard RSA Private key
		final BigInteger totient = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));
		final BigInteger realD = Exponentiation.modInverse(e, totient);
		final RSAPrivateKeySpec privateKeySpec = new RSAPrivateKeySpec(n, realD);
		final RSAPrivateKey privateKey = (RSAPrivateKey) keyFactory.generatePrivate(privateKeySpec);
		System.out.println(" done.");
		
		// Create signature using normal (non-threshold) signing
		System.out.print("  Generating signature...");
		final KeyPair keyPair = new KeyPair(publicKey, privateKey);
		final Cipher signingContext = Cipher.getInstance("RSA/ECB/NoPadding");
		signingContext.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());
		final byte[] hashed = MessageDigest.getInstance(CommonConfiguration.HASH_ALGORITHM).digest(toBeSigned);
		signingContext.update(hashed);
		final byte[] signature = signingContext.doFinal();
		System.out.println(" done.");

		// Create secret shares of "d"
		System.out.print("  Generating secret shares...");
		final BigInteger d = Exponentiation.modInverse(e, m);// ModularArithmetic.modInverse(e, m);

		// Generate random polynomial coefficients for secret sharing of d
		final BigInteger[] coefficients = RandomNumberGenerator.generateRandomArray(threshold, m);

		// Set the secret as the first coefficient
		coefficients[0] = d;

		// Evaluate the polynomial from 1 to numSevers (must not evaluate at zero!)
		final ShamirShare[] shares = new ShamirShare[servers.length];
		for (int i = 0; i < servers.length; i++) {
			BigInteger xCoord = BigInteger.valueOf(i + 1);
			shares[i] = Polynomials.evaluatePolynomial(coefficients, xCoord, m);
		}
		System.out.println(" done.");

		// Generate public and private verification keys
		System.out.print("  Creating public and private verification keys...");

		// Generate public verification key v as a random square modulo n
		final BigInteger sqrtV = RandomNumberGenerator.generateRandomInteger(n);
		final BigInteger v = sqrtV.modPow(ThresholdSignatures.TWO, n);

		// Generate private verification keys as v^share mod n
		final BigInteger[] verificationKeys = new BigInteger[shares.length];
		for (int i = 0; i < shares.length; i++) {
			verificationKeys[i] = v.modPow(shares[i].getY(), n);
		}
		System.out.println(" done.");

		// Register information with servers for later
		System.out.print("  Storing configuration to servers...");
		ServerPublicConfiguration publicConfig = new ServerPublicConfiguration(serverCount, threshold, n, e, v,
				verificationKeys);

		for (int i = 0; i < servers.length; i++) {
			final RsaSignatureServer server = servers[i];
			final ShamirShare share = shares[i];
			if (!server.register(username, publicConfig, share)) {
				throw new BelowThresholdException("Failed to register with server: " + i);
			}
		}
		System.out.println(" done.");
		
		return signature;
	}

}
