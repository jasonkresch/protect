package com.ibm.pross.common.util;

import java.math.BigInteger;

import com.squareup.jnagmp.Gmp;

public class Exponentiation {

	public static final boolean GMP_AVAILABLE;

	static {
		GMP_AVAILABLE = canLoadGmp();
	}

	private static boolean canLoadGmp() {
		try {
			Gmp.checkLoaded();
			return true;
		} catch (Error e) {
			System.err.println("Unable to use GMP for modular exponentiation: " + e.getMessage());
			return false;
		}
	}

	/**
	 * If available, this method uses the GMP library to perform a secure modular
	 * exponentiation.
	 * 
	 * Otherwise it falls back to Java's BigInteger implementation which is not
	 * secure against timing attacks. (This can leak the exponent unless blinding
	 * methods are employed)
	 * 
	 * @param base
	 * @param exponent
	 * @param modulus
	 * 
	 * @return (base ^ exponent) % modulus
	 */
	public static BigInteger modPowSecure(final BigInteger base, final BigInteger exponent, final BigInteger modulus) {
		if (GMP_AVAILABLE) {
			return exponent.signum() < 0 // Gmp library can't handle negative exponents
					? modInverse(Gmp.modPowSecure(base, exponent.negate(), modulus), modulus)
					: Gmp.modPowSecure(base, exponent, modulus);
		} else {
			// Generate blinding factor to obfsucate the exponent
			return modPowerSecureJava(base, exponent, modulus);
		}
	}

	/**
	 * Performs an exponentiation in a way that prevents side-channel attacks. Note
	 * that this method takes about twice the time to compute.
	 * 
	 * @param base
	 * @param exponent
	 * @param modulus
	 * @return
	 */
	public static BigInteger modPowerSecureJava(final BigInteger base, final BigInteger exponent,
			final BigInteger modulus) {
		throw new RuntimeException("Not yet implemented");
//		
//		// Generate blinding factor to obfsucate the exponent
//		final BigInteger mMinusOne = modulus.subtract(BigInteger.ONE);
//		final BigInteger x = RandomNumberGenerator.generateRandomCoprimeInRange(modulus);
//
//		// Blind the exponent
//		final BigInteger blindedExponent = exponent.add(x).mod(modulus);
//
//		// Compute the power
//		final BigInteger blindedPower = base.modPow(blindedExponent, modulus);
//
//		// Unblind the result
//		//final BigInteger xInverse = x.modInverse(mMinusOne);
//		final BigInteger unblindedResult = blindedPower.modPow(x.negate(), modulus);
//
//		return unblindedResult;
	}

	/**
	 * If available, uses the GMP library to perform a modular exponentiation.
	 * 
	 * Note that this implementation is not secure against timing attacks. If
	 * security of the exponent is required use modPowSecure.
	 * 
	 * @param base
	 * @param exponent
	 * @param modulus
	 * 
	 * @return (base ^ exponent) % modulus
	 * 
	 * @see modPowSecure
	 */
	public static BigInteger modPow(BigInteger base, BigInteger exponent, BigInteger modulus) {
		if (GMP_AVAILABLE) {
			return exponent.signum() < 0 // Gmp library can't handle negative exponents
					? modInverse(Gmp.modPowInsecure(base, exponent.negate(), modulus), modulus)
					: Gmp.modPowInsecure(base, exponent, modulus);
		} else {
			return base.modPow(exponent, modulus);
		}
	}

	/**
	 * Computes the modular multiplicitive inverse of a number
	 *
	 * @param a
	 *            The number to compute the inverse of
	 * @param b
	 *            The modulus
	 * 
	 * @return the inverse of a modulo b
	 * 
	 * @throws ArithmeticException
	 *             if there is no inverse
	 */
	public static BigInteger modInverse(final BigInteger a, final BigInteger modulus) throws ArithmeticException {
		if (GMP_AVAILABLE) {
			return Gmp.modInverse(a, modulus);
		} else {
			return a.modInverse(modulus);
		}
	}

}
