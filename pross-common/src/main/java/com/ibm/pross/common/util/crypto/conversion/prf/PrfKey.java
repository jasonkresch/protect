package com.ibm.pross.common.util.crypto.conversion.prf;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Hex;

public class PrfKey {

	private final byte[] keyBytes;

	public PrfKey(final byte[] keyBytes) {
		this.keyBytes = keyBytes.clone();
	}

	public PrfKey(final SecretKey key) {
		this.keyBytes = key.getEncoded();
	}

	public SecretKey getKey(final String algorithm) {
		return new SecretKeySpec(getKeyBytes(), algorithm);
	}

	public byte[] getKeyBytes() {
		return this.keyBytes.clone();
	}

	@Override
	public String toString() {
		return "[PrfKey=" + Hex.encodeHexString(keyBytes) + "]";
	}

}
