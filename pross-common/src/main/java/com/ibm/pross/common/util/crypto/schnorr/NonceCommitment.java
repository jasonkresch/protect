package com.ibm.pross.common.util.crypto.schnorr;

import java.math.BigInteger;

import com.ibm.pross.common.util.RandomNumberGenerator;
import com.ibm.pross.common.util.crypto.ecc.EcCurve;
import com.ibm.pross.common.util.crypto.ecc.EcPoint;

/**
 * This class is meant to cache a FROST ( https://eprint.iacr.org/2020/852.pdf )
 * commitment to a nonce in a threshold Schnorr signing operation
 */
public class NonceCommitment {

	private final BigInteger d;
	private final BigInteger e;
	private final EcPoint gD;
	private final EcPoint gE;

	public NonceCommitment(final BigInteger d, final BigInteger e, final EcPoint gD, final EcPoint gE) {
		this.d = d;
		this.e = e;
		this.gD = gD;
		this.gE = gE;
	}

	public static NonceCommitment generateCommitment(EcCurve curve) {
		final BigInteger fieldModulus = curve.getR();
		final BigInteger e = RandomNumberGenerator.generateRandomPositiveInteger(fieldModulus);
		final BigInteger d = RandomNumberGenerator.generateRandomPositiveInteger(fieldModulus);
		final EcPoint gE = curve.multiply(curve.getG(), e);
		final EcPoint gD = curve.multiply(curve.getG(), d);
		return new NonceCommitment(e, d, gE, gD);
	}

	public BigInteger getD() {
		return d;
	}

	public BigInteger getE() {
		return e;
	}

	public EcPoint getgD() {
		return gD;
	}

	public EcPoint getgE() {
		return gE;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((d == null) ? 0 : d.hashCode());
		result = prime * result + ((e == null) ? 0 : e.hashCode());
		result = prime * result + ((gD == null) ? 0 : gD.hashCode());
		result = prime * result + ((gE == null) ? 0 : gE.hashCode());
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
		NonceCommitment other = (NonceCommitment) obj;
		if (d == null) {
			if (other.d != null)
				return false;
		} else if (!d.equals(other.d))
			return false;
		if (e == null) {
			if (other.e != null)
				return false;
		} else if (!e.equals(other.e))
			return false;
		if (gD == null) {
			if (other.gD != null)
				return false;
		} else if (!gD.equals(other.gD))
			return false;
		if (gE == null) {
			if (other.gE != null)
				return false;
		} else if (!gE.equals(other.gE))
			return false;
		return true;
	}
	
	

}
