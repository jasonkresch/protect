package com.ibm.pross.server.p2p.messages;

import java.io.Serializable;

import com.ibm.pross.server.pvss.exponent.PublicKey;

public class MessageSignature implements Serializable {

	private static final long serialVersionUID = -3853919532469424397L;

	private final String signatureAlgorithm;
	private final PublicKey publicKey;

	public MessageSignature(String signatureAlgorithm, PublicKey publicKey) {
		this.signatureAlgorithm = signatureAlgorithm;
		this.publicKey = publicKey;
	}

	public String getSignatureAlgorithm() {
		return signatureAlgorithm;
	}

	public PublicKey getPublicKey() {
		return publicKey;
	}

	@Override
	public String toString() {
		return "MessageSignature [signatureAlgorithm=" + signatureAlgorithm + ", publicKey=" + publicKey + "]";
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((publicKey == null) ? 0 : publicKey.hashCode());
		result = prime * result + ((signatureAlgorithm == null) ? 0 : signatureAlgorithm.hashCode());
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
		MessageSignature other = (MessageSignature) obj;
		if (publicKey == null) {
			if (other.publicKey != null)
				return false;
		} else if (!publicKey.equals(other.publicKey))
			return false;
		if (signatureAlgorithm == null) {
			if (other.signatureAlgorithm != null)
				return false;
		} else if (!signatureAlgorithm.equals(other.signatureAlgorithm))
			return false;
		return true;
	}

}
