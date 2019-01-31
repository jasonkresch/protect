/*
 * Copyright (c) IBM Corporation 2018. All Rights Reserved.
 * Project name: pross
 * This project is licensed under the MIT License, see LICENSE.
 */

package com.ibm.pross.common.util;

import java.math.BigInteger;
import java.security.SecureRandom;

/**
 * Implements methods for securely generating random numbers and bytes
 */
public class RandomNumberGenerator {

	/**
	 * Generates a cryptographically secure big integer randomly chosen from the
	 * range (0 .. 2^bitlength - 1) inclusive
	 * 
	 * @param bitLength
	 * @return A random integer
	 */
	public static BigInteger generateRandomInteger(int bitLength) {
		return new BigInteger(bitLength, new SecureRandom());
	}

	/**
	 * Generates a cryptographically secure big integer randomly chosen from the
	 * range (0 .. max - 1) inclusive
	 * 
	 * @param max
	 * @return
	 */
	public static BigInteger generateRandomInteger(BigInteger max) {
		BigInteger num;
		do {
			num = generateRandomInteger(max.bitLength());
		} while (num.compareTo(max) >= 0);
		return num;
	}

	/**
	 * Generates a cryptographically secure big integer randomly chosen from the
	 * range (1 .. max - 1) inclusive
	 * 
	 * @param max
	 * @return
	 */
	public static BigInteger generateRandomPositiveInteger(BigInteger max) {
		BigInteger num;
		do {
			num = generateRandomInteger(max);
		} while (num.compareTo(BigInteger.ONE) < 0);
		return num;
	}

	/**
	 * Generates a cryptographically secure big integer chosen from the range (1 ..
	 * m - 1) inclusive, which is guaranted to be co-prime with m. This is required
	 * in some applications.
	 * 
	 * @param m
	 * @return
	 */
	public static BigInteger generateRandomCoprimeInRange(final BigInteger m) {
		while (true) {
			final BigInteger x = RandomNumberGenerator.generateRandomPositiveInteger(m);
			if (x.gcd(m).equals(BigInteger.ONE)) {
				return x;
			}
		}
	}

	/**
	 * Generates a cryptographically secure random byte array
	 * 
	 * @param bitLength
	 * @return
	 */
	public static byte[] generateRandomBytes(int bitLength) {
		SecureRandom random = new SecureRandom();
		byte[] array = new byte[bitLength / 8];
		random.nextBytes(array);
		return array;
	}

	/**
	 * Generates an array of big integer of the specified size and for the specified
	 * range
	 * 
	 * @param size
	 *            Size of the list to create
	 * @param max
	 *            Maximum range on the size of the randomly selected big integers
	 * @return Array of big integers, each on the range of (0, max - 1), inclusive
	 */
	public static BigInteger[] generateRandomArray(int size, BigInteger max) {
		BigInteger list[] = new BigInteger[size];
		for (int i = 0; i < list.length; i++) {
			list[i] = generateRandomInteger(max);
		}
		return list;
	}

}
