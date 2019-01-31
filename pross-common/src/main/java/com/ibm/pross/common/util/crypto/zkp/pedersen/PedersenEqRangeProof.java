package com.ibm.pross.common.util.crypto.zkp.pedersen;

import java.io.Serializable;
import java.math.BigInteger;

import com.ibm.pross.common.util.crypto.ecc.EcPoint;

public class PedersenEqRangeProof implements Serializable {

	private static final long serialVersionUID = 4066675352715186273L;

	// Proof fields
	private final BigInteger Ealpha;
	private final BigInteger Ebeta;
	private final EcPoint S1;
	private final BigInteger z1;
	private final BigInteger z2;
	private final BigInteger e1;
	private final BigInteger e2;

	public PedersenEqRangeProof(final BigInteger Ealpha, BigInteger Ebeta, final EcPoint S1, final BigInteger z1,
			final BigInteger z2, final BigInteger e1, BigInteger e2) {
		this.Ealpha = Ealpha;
		this.Ebeta = Ebeta;
		this.S1 = S1;
		this.z1 = z1;
		this.z2 = z2;
		this.e1 = e1;
		this.e2 = e2;
	}

	public BigInteger getEalpha() {
		return Ealpha;
	}

	public BigInteger getEbeta() {
		return Ebeta;
	}

	public EcPoint getS1() {
		return S1;
	}

	public BigInteger getZ1() {
		return z1;
	}

	public BigInteger getZ2() {
		return z2;
	}

	public BigInteger getE1() {
		return e1;
	}

	public BigInteger getE2() {
		return e2;
	}

	@Override
	public String toString() {
		return "PedersenEqRangeProof [Ealpha=" + Ealpha + ", Ebeta=" + Ebeta + ", S1=" + S1 + ", z1=" + z1 + ", z2="
				+ z2 + ", e1=" + e1 + ", e2=" + e2 + "]";
	}

	public long getSize() {
		return Ealpha.toByteArray().length + Ebeta.toByteArray().length + (S1.getX().toByteArray().length + 1)
				+ z1.toByteArray().length + z2.toByteArray().length + e1.toByteArray().length + e2.toByteArray().length;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((Ealpha == null) ? 0 : Ealpha.hashCode());
		result = prime * result + ((Ebeta == null) ? 0 : Ebeta.hashCode());
		result = prime * result + ((S1 == null) ? 0 : S1.hashCode());
		result = prime * result + ((e1 == null) ? 0 : e1.hashCode());
		result = prime * result + ((e2 == null) ? 0 : e2.hashCode());
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
		PedersenEqRangeProof other = (PedersenEqRangeProof) obj;
		if (Ealpha == null) {
			if (other.Ealpha != null)
				return false;
		} else if (!Ealpha.equals(other.Ealpha))
			return false;
		if (Ebeta == null) {
			if (other.Ebeta != null)
				return false;
		} else if (!Ebeta.equals(other.Ebeta))
			return false;
		if (S1 == null) {
			if (other.S1 != null)
				return false;
		} else if (!S1.equals(other.S1))
			return false;
		if (e1 == null) {
			if (other.e1 != null)
				return false;
		} else if (!e1.equals(other.e1))
			return false;
		if (e2 == null) {
			if (other.e2 != null)
				return false;
		} else if (!e2.equals(other.e2))
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

}