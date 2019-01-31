package com.ibm.pross.server.app.dkgnew;

import java.io.Serializable;
import java.math.BigInteger;

import com.ibm.pross.common.util.crypto.ecc.EcPoint;

public class ZeroKnowledgeProof implements Serializable {

	private static final long serialVersionUID = -6024081375884538678L;

	private final EcPoint A0;
	private final EcPoint B0;
	private final BigInteger c;
	private final BigInteger sa;
	private final BigInteger sb;

	public ZeroKnowledgeProof(final EcPoint A0, final EcPoint B0, final BigInteger c, final BigInteger sa,
			final BigInteger sb) {
		this.A0 = A0;
		this.B0 = B0;
		this.c = c;
		this.sa = sa;
		this.sb = sb;
	}

	public EcPoint getA0() {
		return A0;
	}

	public EcPoint getB0() {
		return B0;
	}

	public BigInteger getC() {
		return c;
	}

	public BigInteger getSa() {
		return sa;
	}

	public BigInteger getSb() {
		return sb;
	}

	@Override
	public String toString() {
		return "ZeroKnowledgeProof [A0=" + A0 + ", B0=" + B0 + ", c=" + c + ", sa=" + sa + ", sb=" + sb + "]";
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((A0 == null) ? 0 : A0.hashCode());
		result = prime * result + ((B0 == null) ? 0 : B0.hashCode());
		result = prime * result + ((c == null) ? 0 : c.hashCode());
		result = prime * result + ((sa == null) ? 0 : sa.hashCode());
		result = prime * result + ((sb == null) ? 0 : sb.hashCode());
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
		ZeroKnowledgeProof other = (ZeroKnowledgeProof) obj;
		if (A0 == null) {
			if (other.A0 != null)
				return false;
		} else if (!A0.equals(other.A0))
			return false;
		if (B0 == null) {
			if (other.B0 != null)
				return false;
		} else if (!B0.equals(other.B0))
			return false;
		if (c == null) {
			if (other.c != null)
				return false;
		} else if (!c.equals(other.c))
			return false;
		if (sa == null) {
			if (other.sa != null)
				return false;
		} else if (!sa.equals(other.sa))
			return false;
		if (sb == null) {
			if (other.sb != null)
				return false;
		} else if (!sb.equals(other.sb))
			return false;
		return true;
	}
	
	

}
