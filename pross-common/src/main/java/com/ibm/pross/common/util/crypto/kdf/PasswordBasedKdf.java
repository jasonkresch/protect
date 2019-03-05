package com.ibm.pross.common.util.crypto.kdf;

import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

public class PasswordBasedKdf {

	// TODO: Add scrypt/bcrypt/

	public static byte[] pbkdf2(final char[] password, final byte[] salt, final int iterations, final int keyLength) {
		try {
			final SecretKeyFactory secretKeyFacotry = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512");
			final PBEKeySpec pbeSpec = new PBEKeySpec(password, salt, iterations, keyLength);
			return secretKeyFacotry.generateSecret(pbeSpec).getEncoded();
		} catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
			throw new RuntimeException(e);
		}
	}

}
