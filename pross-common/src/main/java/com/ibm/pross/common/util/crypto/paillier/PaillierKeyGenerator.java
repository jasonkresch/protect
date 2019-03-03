package com.ibm.pross.common.util.crypto.paillier;

import java.math.BigInteger;
import java.security.SecureRandom;

public class PaillierKeyGenerator {

	public static final int DEFAULT_KEY_LEN = 2048;

	private final int keyLength;

	public PaillierKeyGenerator() {
		this(PaillierKeyGenerator.DEFAULT_KEY_LEN);
	}

	public PaillierKeyGenerator(final int keyLength) {

		if (keyLength < 1024) {
			throw new IllegalArgumentException("Key Length must be greater than or equal to 1024");
		}

		this.keyLength = keyLength;
	}

	public PaillierKeyPair generate() {
		final SecureRandom random = new SecureRandom();

		final BigInteger p = BigInteger.probablePrime(this.keyLength / 2, random); // random prime
		final BigInteger q = BigInteger.probablePrime(this.keyLength / 2, random); // random prime

		final BigInteger n = p.multiply(q); // p*q
		final BigInteger nSquared = n.multiply(n); // n^2

		final BigInteger pMinusOne = p.subtract(BigInteger.ONE); // p - 1
		final BigInteger qMinusOne = q.subtract(BigInteger.ONE); // q - 1

		final BigInteger lambda = pMinusOne.multiply(qMinusOne); // totient(n)
		final BigInteger g = n.add(BigInteger.ONE); // n + 1
		final BigInteger mu = lambda.modInverse(n); // lambda^-1 % n

		final PaillierPublicKey publicKey = new PaillierPublicKey(n, g, nSquared);
		final PaillierPrivateKey privateKey = new PaillierPrivateKey(lambda, mu, n, nSquared);
		
		return new PaillierKeyPair(publicKey, privateKey);
	}
	
}
