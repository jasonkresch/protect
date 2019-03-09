package com.ibm.pross.common.util;

import java.math.BigInteger;
import java.security.SecureRandom;

/**
 * Implements useful functions related to finding and testing for primes with
 * certain characteristics
 */
public class Primes {

	public static final int PRIMALITY_TEST_STRENGTH = 100;

	public final static BigInteger TWO = BigInteger.valueOf(2);

	/**
	 * Determines if this number is a probable prime with an error level of (1 /
	 * 2^PRIMALITY_TEST_STRENGTH)
	 * 
	 * @param candidatePrime
	 * @return True if the number is probably prime, false if it is definitely not a
	 *         prime
	 */
	public static boolean isPrime(final BigInteger candidatePrime) {
		return candidatePrime.isProbablePrime(PRIMALITY_TEST_STRENGTH);
	}

	/**
	 * Generates a prime number of the requested number of bits using a
	 * cryptographically secure random number generator.
	 * 
	 * @param bitLength
	 * @return A BigInteger representing a randomly prime number.
	 */
	public static BigInteger generatePrime(final int bitLength) {
		return BigInteger.probablePrime(bitLength, new SecureRandom());
	}

	/**
	 * Generates a Sophie-Germain prime number of the requested number of bits using
	 * a cryptographically secure random number generator.
	 * 
	 * A Sophie-Germain prime is a prime p such that 2p+1 is also prime.
	 * 
	 * @param bitLength
	 * @return A BigInteger representing a randomly prime number.
	 */
	public static BigInteger generateSophieGermainPrime(final int bitLength) {
		while (true) {
			BigInteger p = generatePrime(bitLength);

			// Returns null if p is not a sophie-germain prime
			BigInteger q = getSafePrime(p);
			if (q != null) {
				return p;
			}
		}
	}

	/**
	 * Generates a Safe Prime number of the requested number of bits using a
	 * cryptographically secure random number generator.
	 * 
	 * A Same-Prime prime is a prime p such that (p-1)/2 is also prime.
	 * 
	 * @param bitLength
	 * @return A BigInteger representing a randomly prime number.
	 */
	public static BigInteger generateSafePrime(final int bitLength) {
		while (true) {
			BigInteger p = generatePrime(bitLength);

			// Returns null if p is not a sophie-germain prime
			final BigInteger q = getSophieGermainPrime(p);
			if (q != null) {
				return p;
			}
		}
	}

	/**
	 * Returns the corresponding "safe prime" from a given Sophie-Germain prime
	 * prime
	 * 
	 * @param sophieGermainPrime
	 * @return
	 */
	public static BigInteger getSafePrime(final BigInteger sophieGermainPrime) {
		BigInteger safePrime = (sophieGermainPrime.multiply(TWO)).add(BigInteger.ONE);
		if (safePrime.isProbablePrime(PRIMALITY_TEST_STRENGTH)) {
			return safePrime;
		} else {
			return null;
		}

	}

	/**
	 * Returns the corresponding sophie-germain prime from a given "safe prime"
	 * prime
	 * 
	 * @param sophieGermainPrime
	 * @return
	 */
	public static BigInteger getSophieGermainPrime(final BigInteger safePrime) {
		BigInteger sophieGermainPrime = safePrime.subtract(BigInteger.ONE).divide(TWO);
		if (sophieGermainPrime.isProbablePrime(PRIMALITY_TEST_STRENGTH)) {
			return sophieGermainPrime;
		} else {
			return null;
		}
	}

}
