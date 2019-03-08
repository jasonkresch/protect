/*
 * Copyright (c) IBM Corporation 2018. All Rights Reserved.
 * Project name: pross
 * This project is licensed under the MIT License, see LICENSE.
 */

package com.ibm.pross.common.util.crypto.kdf;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * Implements HKDF standard (RFC 5869) https://tools.ietf.org/html/rfc5869
 * 
 * Described and analyzed here: https://eprint.iacr.org/2010/264.pdf
 * 
 * @author jresch
 */
public class HmacKeyDerivationFunction {

	public static final String HDFK_SHA512 = "HMACSHA512";
	
	private final String hmacAlgorithm;
	private final byte[] prfKey;
	private final int hashLength;

	private static Mac getHmac(final String hmacAlgorithm) {
		try {
			return Mac.getInstance(hmacAlgorithm);
		} catch (NoSuchAlgorithmException e) {
			throw new IllegalArgumentException("Invalid HMAC algorithm");
		}
	}

	private static int getHashLen(final String hmacAlgorithm) {
		return getHmac(hmacAlgorithm).getMacLength();
	}

	public HmacKeyDerivationFunction(final String hmacAlgorithm, final byte[] inputKeyingMaterial) {
		this(hmacAlgorithm, inputKeyingMaterial, new byte[0]);
	}

	/**
	 * Extracts a PRF key from the provided input keying material, using the
	 * "HKDF-Extract" operation.
	 * 
	 * @param hmacAlgorithm
	 *            The HMAC algorithm to use as the basis of key derivation. For
	 *            example "HMAC-SHA256" or "HMAC-SHA512".
	 * @param inputKeyingMaterial
	 *            The entropy source which may or may not be conditioned.
	 * @param salt
	 *            optional salt value (a non-secret random value); if not
	 *            provided, it is set to a string of HashLen zeros.
	 */
	public HmacKeyDerivationFunction(final String hmacAlgorithm, byte[] inputKeyingMaterial, byte[] salt) {
		// Compute the PRF key
		Mac hmac = getHmac(hmacAlgorithm);
		try {
			if (salt.length == 0)
				hmac.init(new SecretKeySpec(new byte[getHashLen(hmacAlgorithm)], hmacAlgorithm));
			else
				hmac.init(new SecretKeySpec(salt, hmacAlgorithm));
		} catch (InvalidKeyException e) {
			throw new RuntimeException("Should not happen", e);
		}

		// Store member variables
		this.hmacAlgorithm = hmacAlgorithm;
		this.prfKey = hmac.doFinal(inputKeyingMaterial);
		this.hashLength = hmac.getMacLength();
		assert this.hashLength == this.prfKey.length;
	}

	protected byte[] getPrfKey()
	{
		return this.prfKey.clone();
	}
	
	/**
	 * Creates a key using the "HKDF-Expand" operation
	 * 
	 * @param length
	 *            The desired length of the requested key. This value must be
	 *            less than 255*hashLength.
	 * @return The derived key
	 */
	public byte[] createKey(final int length) {
		return createKey(new byte[0], length);
	}

	/**
	 * Creates a key using the "HKDF-Expand" operation
	 * 
	 * @param info
	 *            optional context and application specific information (can be
	 *            a zero-length string). This method uses the UTF-8 encoding of
	 *            the string.
	 * @param length
	 *            The desired length of the requested key. This value must be
	 *            less than 255*hashLength.
	 * @return The derived key
	 */
	public byte[] createKey(final String info, final int length) {
		return createKey(info.getBytes(StandardCharsets.UTF_8), length);
	}

	/**
	 * Creates a key using the "HKDF-Expand" operation
	 * 
	 * @param info
	 *            optional context and application specific information (can be
	 *            a zero-length string).
	 * @param length
	 *            The desired length of the requested key. This value must be
	 *            less than 255*hashLength.
	 * @return
	 * 	The derived key
	 */
	public byte[] createKey(final byte[] info, final int length)
	{
		if (length > (255*this.hashLength))
		{
			throw new IllegalArgumentException("Provided length of " + length + " exceeds maximum of " + (255*this.hashLength));
		}
		
		// Initialize HMAC object with PRF key
		final Mac hmac = getHmac(hmacAlgorithm);
		try {
			hmac.init(new SecretKeySpec(this.prfKey, hmacAlgorithm));
		} catch (InvalidKeyException e) {
			throw new RuntimeException("Should not happen", e);
		}
		
		final ByteArrayOutputStream bos = new ByteArrayOutputStream();
		byte[] previousHash = new byte[0];
		byte iteration = 1;
		
		while (bos.size() < length)
		{
			// Process data
			hmac.update(previousHash);
			hmac.update(info);
			hmac.update(iteration);
			
			// Invoke HMAC using the PRF key
			final byte[] hmacResult = hmac.doFinal();
			bos.write(hmacResult, 0, hmacResult.length);
			
			// Setup next iteration
			previousHash = hmacResult;
			iteration++;
		}
		
		// Take left-most bytes
		final byte[] collectedBytes = bos.toByteArray();
		byte[] outputKeyingMaterial = new byte[length];
		System.arraycopy(collectedBytes, 0, outputKeyingMaterial, 0, length);
		
		return outputKeyingMaterial;
	}

}
