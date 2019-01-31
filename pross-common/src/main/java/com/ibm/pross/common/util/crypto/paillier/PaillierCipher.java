package com.ibm.pross.common.util.crypto.paillier;

import java.math.BigInteger;

import com.ibm.pross.common.util.Exponentiation;
import com.ibm.pross.common.util.RandomNumberGenerator;

public class PaillierCipher {

	private static BigInteger l(final BigInteger u, final BigInteger n) {
		return u.subtract(BigInteger.ONE).divide(n); // L(u) = (u-1) / n
	}

	public static BigInteger encrypt(final PaillierPublicKey encryptionKey, final BigInteger message) {
		final BigInteger n = encryptionKey.getN();
		final BigInteger r = RandomNumberGenerator.generateRandomCoprimeInRange(n);
		return encrypt(encryptionKey, message, r);
	}

	public static BigInteger encrypt(final PaillierPublicKey encryptionKey, final BigInteger message,
			final BigInteger r) {

		// Get public key parameters
		//final BigInteger g = encryptionKey.getG();
		final BigInteger n = encryptionKey.getN();
		final BigInteger nSquared = encryptionKey.getNSquared();

		// This works for any g
		//final BigInteger ciphertext = Exponentiation.modPow(g, message, nSquared);
		
		// WARNING: This works only for cases where for g = n + 1
		final BigInteger ciphertext = n.multiply(message).add(BigInteger.ONE).mod(nSquared);
		
		final BigInteger obfuscation = Exponentiation.modPow(r, n, nSquared);
		
		return ciphertext.multiply(obfuscation).mod(nSquared);
	}

	public static BigInteger decrypt(final PaillierPrivateKey decryptionKey, final BigInteger ciphertext) {

		// Get private key parameters
		final BigInteger lambda = decryptionKey.getLambda();
		final BigInteger mu = decryptionKey.getMu();
		final BigInteger n = decryptionKey.getN();
		final BigInteger nSquared = decryptionKey.getNSquared();

		final BigInteger innerPart = Exponentiation.modPow(ciphertext, lambda, nSquared);
		return l(innerPart, n).multiply(mu).mod(n);
	}

}
