package com.ibm.pross.common.util.crypto.zkp.feldman;

import java.io.Serializable;
import java.math.BigInteger;

import com.ibm.pross.common.util.crypto.ecc.EcPoint;

public class FeldmanEqRangeProof implements Serializable {

	private static final long serialVersionUID = 968857084310495016L;

	// Proof fields
	private final BigInteger E1;
	private final EcPoint S1;
	private final BigInteger z;
	private final BigInteger z1;
	private final BigInteger z2;

	public FeldmanEqRangeProof(final BigInteger E1, final EcPoint S1, final BigInteger z, final BigInteger z1,
			final BigInteger z2) {
		this.E1 = E1;
		this.S1 = S1;
		this.z = z;
		this.z1 = z1;
		this.z2 = z2;
	}

	@Override
	public String toString() {
		return "EqRangeProof [E1=" + E1 + ", S1=" + S1 + ", z=" + z + ", z1=" + z1 + ", z2=" + z2 + "]";
	}

	public BigInteger getE1() {
		return E1;
	}

	public EcPoint getS1() {
		return S1;
	}

	public BigInteger getZ() {
		return z;
	}

	public BigInteger getZ1() {
		return z1;
	}

	public BigInteger getZ2() {
		return z2;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((E1 == null) ? 0 : E1.hashCode());
		result = prime * result + ((S1 == null) ? 0 : S1.hashCode());
		result = prime * result + ((z == null) ? 0 : z.hashCode());
		result = prime * result + ((z1 == null) ? 0 : z1.hashCode());
		result = prime * result + ((z2 == null) ? 0 : z2.hashCode());
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
		FeldmanEqRangeProof other = (FeldmanEqRangeProof) obj;
		if (E1 == null) {
			if (other.E1 != null)
				return false;
		} else if (!E1.equals(other.E1))
			return false;
		if (S1 == null) {
			if (other.S1 != null)
				return false;
		} else if (!S1.equals(other.S1))
			return false;
		if (z == null) {
			if (other.z != null)
				return false;
		} else if (!z.equals(other.z))
			return false;
		if (z1 == null) {
			if (other.z1 != null)
				return false;
		} else if (!z1.equals(other.z1))
			return false;
		if (z2 == null) {
			if (other.z2 != null)
				return false;
		} else if (!z2.equals(other.z2))
			return false;
		return true;
	}

	public long getSize() {
		return E1.toByteArray().length + (S1.getX().toByteArray().length + 1) + z.toByteArray().length
				+ z1.toByteArray().length + z2.toByteArray().length;
	}

}