package com.ibm.pross.common.util.crypto.conversion.prf;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.NoSuchPaddingException;

/**
 * Computes the output of a PRF given a key
 * 
 * Implementations may cache the initialized PRF for improved performance
 */
public abstract class PseudoRandomFunction {

	public enum PrfAlgorithm
	{
		HMAC,
		AES;
	}
	
	private final PrfKey key;

	public PseudoRandomFunction(final PrfKey key) {
		this.key = key;
	}

	public abstract byte[] computePrf(final byte[] input);

	public PrfKey getKey() {
		return key;
	}

	public static final PseudoRandomFunction create(final PrfAlgorithm prfAlgorithm, final PrfKey prfKey) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException {
		if (PrfAlgorithm.AES.equals(prfAlgorithm)) {
			return new PseudoRandomFunctionAES(prfKey);
		} else if (PrfAlgorithm.HMAC.equals(prfAlgorithm)) {
			return new PseudoRandomFunctionHMAC(prfKey);
		} else {
			throw new IllegalArgumentException("Invalid PRF algorithm name provided");
		}
	}

}
