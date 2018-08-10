/*
 * Copyright (c) IBM Corporation 2018. All Rights Reserved.
 * Project name: pross
 * This project is licensed under the MIT License, see LICENSE.
 */

package com.ibm.pross.common.util.crypto.kdf;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import com.ibm.pross.common.util.crypto.ecc.EcPoint;
import com.ibm.pross.common.util.serialization.Parse;

/**
 * Extracts entropy from derived key and key identifier and uses it to
 * initialize a KDF for creating ciphers or other keys.
 * 
 * @author jresch
 */
public class EntropyExtractor {

	// Declare constants
	private static final byte[] AES_256_KEY = "aes-256-key".getBytes(StandardCharsets.UTF_8);
	private static final byte[] AES_GCM_IV = "aes-gcm-iv".getBytes(StandardCharsets.UTF_8);
	private static int AES_KEY_LENGTH_BITS = 256;
	private static int GCM_TAG_LENGTH_BITS = 96;

	/**
	 * Implements outer hash of 2HashTDF defined in TOPPSS paper (
	 * https://eprint.iacr.org/2017/363.pdf ), and uses OPRF output as PRF key
	 * to initialize a KDF, see "TOPPSS: Cost-minimal Password-Protected Secret
	 * Sharing based on Threshold OPRF"
	 * 
	 * @param oprfInput
	 * @param ecPoint
	 * @return
	 */
	public static HmacKeyDerivationFunction getKeyGenerator(final byte[] oprfInput, final EcPoint ecPoint) {

		// Concatenate key identifier with the x-coordinate from the derived
		// result
		final byte[] concatenation = Parse.concatenate(oprfInput, ecPoint.getX().toByteArray());

		// Initialize a KDF from the key identifier and the derived result
		return new HmacKeyDerivationFunction(HmacKeyDerivationFunction.HDFK_SHA512, concatenation);
	}

	/**
	 * Given an initialized KDF, produces a consistent AES-GCM cipher,
	 * initialized for either encryption or decryption. This cipher must only be
	 * used to encrypt a single message!
	 * 
	 * @param hkdf
	 * @param cipherMode
	 *            Either Cipher.ENCRYPT_MODE or Cipher.DECRYPT_MODE
	 * @return
	 * @throws GeneralSecurityException
	 */
	public static Cipher getCipher(final HmacKeyDerivationFunction hkdf, int cipherMode) {

		try {
			// Derive a Key and IV from the derived result
			final byte[] keyBytes = hkdf.createKey(AES_256_KEY, AES_KEY_LENGTH_BITS / Byte.SIZE);
			final byte[] ivBytes = hkdf.createKey(AES_GCM_IV, GCM_TAG_LENGTH_BITS / Byte.SIZE);

			// Create Cipher
			final Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
			final SecretKeySpec keySpec = new SecretKeySpec(keyBytes, "AES");
			final GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH_BITS, ivBytes);
			cipher.init(cipherMode, keySpec, gcmSpec);

			return cipher;
		} catch (GeneralSecurityException e) {
			throw new RuntimeException(e);
		}
	}
}
