package com.ibm.pross.common.util.crypto.rsa.threshold.sign.data;

import java.math.BigInteger;

/**
 * A pair of integers which together form a proof that can be
 * checked against a signature share to assert its validity
 */
public class SignatureShareProof {

	// A "hash" of some of the parameters of the SignatureShare computation
	private final BigInteger c;
	
	// Equal to the (share*c) + a random value r
	private final BigInteger z;

	public SignatureShareProof(final BigInteger c, final BigInteger z) {
		this.c = c;
		this.z = z;
	}

	public BigInteger getC() {
		return c;
	}
	
	public BigInteger getZ() {
		return z;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((c == null) ? 0 : c.hashCode());
		result = prime * result + ((z == null) ? 0 : z.hashCode());
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
		SignatureShareProof other = (SignatureShareProof) obj;
		if (c == null) {
			if (other.c != null)
				return false;
		} else if (!c.equals(other.c))
			return false;
		if (z == null) {
			if (other.z != null)
				return false;
		} else if (!z.equals(other.z))
			return false;
		return true;
	}

	
}
