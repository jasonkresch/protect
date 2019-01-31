package com.ibm.pross.common.util.crypto.paillier;

import java.io.Serializable;

public class PaillierKeyPair implements Serializable {

	private static final long serialVersionUID = -5051082552217796076L;
	
	private final PaillierPublicKey publicKey;
	private final PaillierPrivateKey privateKey;

	public PaillierKeyPair(final PaillierPublicKey publicKey, final PaillierPrivateKey privateKey) {
		this.publicKey = publicKey;
		this.privateKey = privateKey;
	}

	public PaillierPublicKey getPublicKey() {
		return publicKey;
	}

	public PaillierPrivateKey getPrivateKey() {
		return privateKey;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((privateKey == null) ? 0 : privateKey.hashCode());
		result = prime * result + ((publicKey == null) ? 0 : publicKey.hashCode());
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		PaillierKeyPair other = (PaillierKeyPair) obj;
		if (privateKey == null) {
			if (other.privateKey != null)
				return false;
		} else if (!privateKey.equals(other.privateKey))
			return false;
		if (publicKey == null) {
			if (other.publicKey != null)
				return false;
		} else if (!publicKey.equals(other.publicKey))
			return false;
		return true;
	}

	@Override
	public String toString() {
		return "PaillierKeyPair [publicKey=" + publicKey + ", privateKey=" + privateKey + "]";
	}

}
