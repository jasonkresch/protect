package com.ibm.pross.common.util.crypto.paillier;

import java.io.Serializable;
import java.math.BigInteger;
import java.security.PrivateKey;

public class PaillierPrivateKey implements Serializable, PrivateKey {

	private static final long serialVersionUID = 2764702861842573689L;

	private final BigInteger lambda;
	private final BigInteger mu;
	private final BigInteger n;
	private final BigInteger nSquared;

	public PaillierPrivateKey(final BigInteger lambda, final BigInteger n) {
		this(lambda, lambda.modInverse(n), n, n.multiply(n));
	}
	
	public PaillierPrivateKey(final BigInteger lambda, final BigInteger mu, final BigInteger n) {
		this(lambda, mu, n, n.multiply(n));
	}

	protected PaillierPrivateKey(final BigInteger lambda, final BigInteger mu, final BigInteger n,
			final BigInteger nSquared) {
		this.lambda = lambda;
		this.mu = mu;
		this.n = n;
		this.nSquared = nSquared;
	}

	public BigInteger getLambda() {
		return lambda;
	}

	public BigInteger getMu() {
		return mu;
	}

	public BigInteger getN() {
		return n;
	}

	public BigInteger getNSquared() {
		return nSquared;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((lambda == null) ? 0 : lambda.hashCode());
		result = prime * result + ((mu == null) ? 0 : mu.hashCode());
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
		PaillierPrivateKey other = (PaillierPrivateKey) obj;
		if (lambda == null) {
			if (other.lambda != null)
				return false;
		} else if (!lambda.equals(other.lambda))
			return false;
		if (mu == null) {
			if (other.mu != null)
				return false;
		} else if (!mu.equals(other.mu))
			return false;
		if (n == null) {
			if (other.n != null)
				return false;
		} else if (!n.equals(other.n))
			return false;
		return true;
	}

	@Override
	public String toString() {
		return "PaillierPrivateKey [lambda=" + lambda + ", mu=" + mu + ", n=" + n + "]";
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
