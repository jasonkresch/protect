package com.ibm.pross.server.dkgnew;

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

}
