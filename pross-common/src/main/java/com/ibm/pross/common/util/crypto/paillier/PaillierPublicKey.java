package com.ibm.pross.common.util.crypto.paillier;

import java.io.Serializable;
import java.math.BigInteger;
import java.security.PublicKey;

public class PaillierPublicKey implements Serializable, PublicKey {

	private static final long serialVersionUID = 2199152241546922013L;

	private final BigInteger n;
	private final BigInteger g;
	private final BigInteger nSquared;

	public PaillierPublicKey(final BigInteger n, final BigInteger g) {
		this(n, g, n.multiply(n));
	}

	public PaillierPublicKey(final BigInteger n, final BigInteger g, final BigInteger nSquared) {
		this.n = n;
		this.g = g;
		this.nSquared = nSquared;
	}

	public BigInteger getN() {
		return n;
	}

	public BigInteger getG() {
		return g;
	}

	public BigInteger getNSquared() {
		return nSquared;
	}

	@Override
	public String toString() {
		return "PaillierPublicKey [n=" + n + ", g=" + g + "]";
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((g == null) ? 0 : g.hashCode());
		result = prime * result + ((n == null) ? 0 : n.hashCode());
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
		PaillierPublicKey other = (PaillierPublicKey) obj;
		if (g == null) {
			if (other.g != null)
				return false;
		} else if (!g.equals(other.g))
			return false;
		if (n == null) {
			if (other.n != null)
				return false;
		} else if (!n.equals(other.n))
			return false;
		return true;
	}

	@Override
	public String getAlgorithm() {
		return "PAILLIER";
	}

	@Override
	public String getFormat() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public byte[] getEncoded() {
		// TODO Auto-generated method stub
		return null;
	}

}
