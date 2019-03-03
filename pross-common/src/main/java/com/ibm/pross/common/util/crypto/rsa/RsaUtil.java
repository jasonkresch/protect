package com.ibm.pross.common.util.crypto.rsa;

import java.math.BigInteger;

import com.ibm.pross.common.util.Exponentiation;

public class RsaUtil {

	/**
	 * Computes a "raw" (no padding) RSA signature of a message m given private
	 * exponent d and modulus n
	 * 
	 * @param m The message
	 * @param d The private exponent
	 * @param n The public modulus, which is the product of two primes
	 * @return The digital signature s of message m computed with private key (d, n)
	 */
	public static BigInteger rsaSign(final BigInteger m, final BigInteger d, final BigInteger n) {
		return Exponentiation.modPow(m, d, n);
	}

	/**
	 * Verifies a "raw" (no padding) RSA signature s given public exponent e and
	 * modulus n
	 * 
	 * @param m The message
	 * @param e The public exponent
	 * @param n The public modulus, which is the product of two primes
	 * @return The decrypted signature m of signature s computed with public key (e,
	 *         n)
	 */
	public static BigInteger rsaVerify(final BigInteger s, final BigInteger e, final BigInteger n) {
		return Exponentiation.modPow(s, e, n);
	}

}
