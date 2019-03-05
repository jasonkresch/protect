package com.ibm.pross.common.util.crypto.conversion.prf;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;

public class PseudoRandomFunctionHMAC extends PseudoRandomFunction {

	public static final String ALGORITHM = "HMACSHA256";
	
	private final Mac mac;

	public PseudoRandomFunctionHMAC(final PrfKey key) throws NoSuchAlgorithmException, NoSuchPaddingException,
			InvalidKeyException, InvalidAlgorithmParameterException {
		super(key);

		// Initialize cipher based on AES key
		this.mac = Mac.getInstance(ALGORITHM);
		this.mac.init(key.getKey(ALGORITHM));
	}

	@Override
	public byte[] computePrf(byte[] input) {
		return this.mac.doFinal(input);
	}

}
