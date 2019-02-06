/*
 * Copyright (c) IBM Corporation 2018. All Rights Reserved.
 * Project name: pross
 * This project is licensed under the MIT License, see LICENSE.
 */

package com.ibm.pross.server.util;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECPoint;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.util.Arrays;

import com.ibm.pross.common.CommonConfiguration;
import com.ibm.pross.common.util.RandomNumberGenerator;
import com.ibm.pross.common.util.crypto.ecc.EcCurve;
import com.ibm.pross.common.util.crypto.ecc.EcPoint;
import com.ibm.pross.common.util.crypto.kdf.HmacKeyDerivationFunction;
import com.ibm.pross.common.util.crypto.kdf.EntropyExtractor;
import com.ibm.pross.common.util.serialization.Parse;
import com.ibm.pross.common.util.serialization.Serialization;
import com.ibm.pross.server.messages.EncryptedPayload;
import com.ibm.pross.server.messages.Payload;

/**
 * Implements public key cryptography based on elliptic curves
 * 
 * Implements the "ECIES" algorithm:
 * https://en.wikipedia.org/wiki/Integrated_Encryption_Scheme
 * 
 * Which is based loosely on ElGamal encryption. It uses AES-GCM for encryption
 * and HMAC-SHA256 for message authentication.
 */
public class EciesEncryption {

	// Static fields
	final public static EcCurve curve = CommonConfiguration.CURVE;
	final public static EcPoint G = curve.getG();

	final public static String ALGORITHM = "ECIES";
	final public static byte[] ECIES = ALGORITHM.getBytes(StandardCharsets.UTF_8);

	final public static String HMAC_ALG = "HMAC-SHA256";
	final public static byte[] HMAC = HMAC_ALG.getBytes(StandardCharsets.UTF_8);
	final public static int HMAC_KEY_LEN = 32;

	public static EncryptedPayload encrypt(final Payload payload, final PublicKey recipientPublicKey) {

		// Serialize the content
		final byte[] contentBytes = MessageSerializer.serializePayload(payload);

		// Generate r (we save this as it is needed for rebuttals
		final BigInteger r = generateR();

		// Encrypt the content
		byte[] encryptedBytes = encrypt(contentBytes, r, recipientPublicKey);

		final EncryptedPayload encryptedPayload = new EncryptedPayload(encryptedBytes, ALGORITHM);
		encryptedPayload.rebuttalEvidence = r.toByteArray();
		return encryptedPayload;

	}

	public static Payload decryptPayload(final EncryptedPayload encryptedPayload,
			final PrivateKey recipientPrivateKey) throws BadPaddingException, IllegalBlockSizeException, ClassNotFoundException, IOException {

		// Get the combined ciphertext
		byte[] ciphertext = encryptedPayload.getEncryptedBytes();

		// Decrypt the content
		final byte[] decryptedBytes = decrypt(ciphertext, recipientPrivateKey);

		// Deserialize and return payload
		final Payload payload = MessageSerializer.deserializePayload(decryptedBytes);
		return payload;

	}

	public static Payload decryptPayload(final EncryptedPayload encryptedPayload, final byte[] rebuttalEvidence,
			final PublicKey recipientPublicKey) throws BadPaddingException, IllegalBlockSizeException, ClassNotFoundException, IOException {

		// Get the combined ciphertext
		byte[] ciphertext = encryptedPayload.getEncryptedBytes();

		// Use the r value to get the shared secret and decrypt
		final BigInteger r = new BigInteger(rebuttalEvidence);

			// Decrypt the content
			final byte[] decryptedBytes = decrypt(ciphertext, r, recipientPublicKey);

			// Deserialize and return payload
			final Object o = MessageSerializer.deserializePayload(decryptedBytes);
			if (o instanceof Payload)
			{
				return (Payload) o;
			}
			else
			{
				throw new IOException("Received invalid class serialization");
			}
	}

	public static BigInteger generateR() {
		return RandomNumberGenerator.generateRandomPositiveInteger(curve.getR());
	}

	protected static byte[] encrypt(final byte[] message, final BigInteger r, final PublicKey publicKey) {
		if (publicKey instanceof ECPublicKey) {
			final ECPublicKey ecPublicKey = (ECPublicKey) publicKey;
			final ECPoint javaPoint = ecPublicKey.getW();
			final EcPoint point = new EcPoint(javaPoint.getAffineX(), javaPoint.getAffineY());
			return encrypt(message, r, point);
		} else {
			throw new IllegalArgumentException("Key type must be ECPublicKey!");
		}
	}

	protected static byte[] decrypt(final byte[] ciphertext, final PrivateKey privateKey)
			throws BadPaddingException, IllegalBlockSizeException {
		if (privateKey instanceof ECPrivateKey) {
			final ECPrivateKey ecPrivateKey = (ECPrivateKey) privateKey;
			final BigInteger privateKeyInt = ecPrivateKey.getS();
			return decrypt(ciphertext, privateKeyInt);
		} else {
			throw new IllegalArgumentException("Key type must be ECPublicKey!");
		}
	}

	protected static byte[] decrypt(final byte[] ciphertext, final BigInteger r, PublicKey publicKey)
			throws BadPaddingException, IllegalBlockSizeException {
		if (publicKey instanceof ECPublicKey) {
			final ECPublicKey ecPublicKey = (ECPublicKey) publicKey;
			final ECPoint javaPoint = ecPublicKey.getW();
			final EcPoint point = new EcPoint(javaPoint.getAffineX(), javaPoint.getAffineY());
			return decrypt(ciphertext, r, point);
		} else {
			throw new IllegalArgumentException("Key type must be ECPublicKey!");
		}
	}

	protected static byte[] encrypt(final byte[] message, final BigInteger r, final EcPoint publicKey) {

		try {

			// Calculate R (our DH public value)
			final EcPoint R = curve.multiply(G, r);

			// Calculate shared secret
			final EcPoint sharedSecret = curve.multiply(publicKey, r);

			// Setup key generator
			final HmacKeyDerivationFunction kdf = EntropyExtractor.getKeyGenerator(ECIES, sharedSecret);

			// Get cipher
			final Cipher aesGcmCipher = EntropyExtractor.getCipher(kdf, Cipher.ENCRYPT_MODE);

			// Get hmac
			final byte[] hmacKey = kdf.createKey(HMAC, HMAC_KEY_LEN);
			final Mac hmac = Mac.getInstance(HMAC_ALG);
			hmac.init(new SecretKeySpec(hmacKey, HMAC_ALG));

			// We have all the keys, perform encryption and mac the cipher text
			final byte[] messageCiphertext = aesGcmCipher.doFinal(message);
			final byte[] mac = hmac.doFinal(messageCiphertext);

			// Serialize the public value
			byte[] publicValue = Parse.concatenate(R.getX(), R.getY());

			// Combine all the parts and return
			return Parse.concatenate(publicValue, messageCiphertext, mac);

		} catch (GeneralSecurityException e) {
			throw new RuntimeException(e);
		}
	}

	protected static byte[] decrypt(final byte[] ciphertext, final BigInteger privateKey)
			throws BadPaddingException, IllegalBlockSizeException {

		// Deserialize components of the ciphertext
		final byte[][] combined = Parse.splitArrays(ciphertext);
		if (combined.length != 3) {
			throw new BadPaddingException("Invalid ciphertext");
		}
		final byte[] publicValue = combined[0];
		final byte[] messageCiphertext = combined[1];
		final byte[] macValue = combined[2];
		final byte[][] coordinates = Parse.splitArrays(publicValue);
		if (coordinates.length != 2) {
			throw new BadPaddingException("Invalid public value");
		}
		final BigInteger xCoord = new BigInteger(coordinates[0]);
		final BigInteger yCoord = new BigInteger(coordinates[1]);

		// Recover R (the sender's DH public value)
		final EcPoint R = new EcPoint(xCoord, yCoord);

		// Calculate shared secret
		final EcPoint sharedSecret = curve.multiply(R, privateKey);

		// Setup key generator
		final HmacKeyDerivationFunction kdf = EntropyExtractor.getKeyGenerator(ECIES, sharedSecret);

		// Get cipher
		final Cipher aesGcmCipher = EntropyExtractor.getCipher(kdf, Cipher.DECRYPT_MODE);

		// Get hmac
		final byte[] hmacKey = kdf.createKey(HMAC, HMAC_KEY_LEN);
		try {
			final Mac hmac = Mac.getInstance(HMAC_ALG);
			hmac.init(new SecretKeySpec(hmacKey, HMAC_ALG));

			// Verify the hmac value before proceeding
			final byte[] mac = hmac.doFinal(messageCiphertext);
			if (!Arrays.areEqual(macValue, mac)) {
				throw new BadPaddingException("Invalid HMAC!");
			}
		} catch (NoSuchAlgorithmException | InvalidKeyException e) {
			throw new RuntimeException(e);
		}

		// Pperform decryption
		return aesGcmCipher.doFinal(messageCiphertext);
	}

	protected static byte[] decrypt(final byte[] ciphertext, final BigInteger r, final EcPoint publicKey)
			throws BadPaddingException, IllegalBlockSizeException {

		// Deserialize components of the ciphertext
		final byte[][] combined = Parse.splitArrays(ciphertext);
		if (combined.length != 3) {
			throw new BadPaddingException("Invalid ciphertext");
		}
		final byte[] publicValue = combined[0];
		final byte[] messageCiphertext = combined[1];
		final byte[] macValue = combined[2];
		final byte[][] coordinates = Parse.splitArrays(publicValue);
		if (coordinates.length != 2) {
			throw new BadPaddingException("Invalid public value");
		}
		final BigInteger xCoord = new BigInteger(coordinates[0]);
		final BigInteger yCoord = new BigInteger(coordinates[1]);

		// Recover R (the sender's DH public value)
		final EcPoint R = new EcPoint(xCoord, yCoord);

		// Begin performing checks

		// Ensure that the provided public value is correct for the given r
		final EcPoint recomputedR = curve.multiply(G, r);
		if (!R.equals(recomputedR)) {
			throw new IllegalArgumentException("R value is incorrect");
		}

		// Calculate shared secret based on the private r value
		final EcPoint sharedSecret = curve.multiply(publicKey, r);

		// Setup key generator
		final HmacKeyDerivationFunction kdf = EntropyExtractor.getKeyGenerator(ECIES, sharedSecret);

		// Get cipher
		final Cipher aesGcmCipher = EntropyExtractor.getCipher(kdf, Cipher.DECRYPT_MODE);

		// Get hmac
		final byte[] hmacKey = kdf.createKey(HMAC, HMAC_KEY_LEN);
		try {
			final Mac hmac = Mac.getInstance(HMAC_ALG);
			hmac.init(new SecretKeySpec(hmacKey, HMAC_ALG));

			// Verify the hmac value before proceeding
			final byte[] mac = hmac.doFinal(messageCiphertext);
			if (!Arrays.areEqual(macValue, mac)) {
				throw new BadPaddingException("Invalid HMAC!");
			}
		} catch (NoSuchAlgorithmException | InvalidKeyException e) {
			throw new RuntimeException(e);
		}

		// Pperform decryption
		return aesGcmCipher.doFinal(messageCiphertext);
	}

}
