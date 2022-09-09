package com.ibm.pross.common.util.crypto.schnorr;

import java.math.BigInteger;

import com.ibm.pross.common.util.RandomNumberGenerator;
import com.ibm.pross.common.util.crypto.ecc.EcCurve;
import com.ibm.pross.common.util.crypto.ecc.EcPoint;

/**
 * This class is meant to cache a FROST ( https://eprint.iacr.org/2020/852.pdf )
 * commitment to a nonce in a threshold Schnorr signing operation
 */
public class NonceCommitment implements Comparable<NonceCommitment> {

	private final int participantIndex;
	private final BigInteger dNonce;
	private final BigInteger eNonce;
	private final EcPoint dCommitment;
	private final EcPoint eCommitment;

	/**
	 * Constructor for privately held (by the participant) nonce commitment
	 * 
	 * @param participantIndex
	 * @param dNonce
	 * @param eNonce
	 * @param dCommitment
	 * @param eCommitment
	 */
	public NonceCommitment(final int participantIndex, final BigInteger dNonce, final BigInteger eNonce,
			final EcPoint dCommitment, EcPoint eCommitment) {
		this.participantIndex = participantIndex;
		this.dNonce = dNonce;
		this.eNonce = eNonce;
		this.dCommitment = dCommitment;
		this.eCommitment = eCommitment;
	}

	/**
	 * Constructor for other participants or the aggregator, which does not contain
	 * private nonces
	 * 
	 * @param participantIndex
	 * @param dCommitment
	 * @param eCommitment
	 */
	public NonceCommitment(int participantIndex, EcPoint dCommitment, EcPoint eCommitment) {
		this(participantIndex, null, null, dCommitment, eCommitment);
	}

	public static NonceCommitment generateNonceCommitment(final EcCurve curve, final int participantIndex) {
		final BigInteger fieldModulus = curve.getR();
		final BigInteger dNonce = RandomNumberGenerator.generateRandomPositiveInteger(fieldModulus);
		final BigInteger eNonce = RandomNumberGenerator.generateRandomPositiveInteger(fieldModulus);
		final EcPoint dCommitment = curve.multiply(curve.getG(), dNonce);
		final EcPoint eCommitment = curve.multiply(curve.getG(), eNonce);
		return new NonceCommitment(participantIndex, dNonce, eNonce, dCommitment, eCommitment);
	}

	@Override
	public int compareTo(final NonceCommitment other) {
		return Long.valueOf(this.participantIndex).compareTo(Long.valueOf(other.getParticipantIndex()));
	}

	public int getParticipantIndex() {
		return participantIndex;
	}

	public BigInteger getNonceD() {
		return dNonce;
	}

	public BigInteger getNonceE() {
		return eNonce;
	}

	public EcPoint getCommitmentD() {
		return dCommitment;
	}

	public EcPoint getCommitmentE() {
		return eCommitment;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((dCommitment == null) ? 0 : dCommitment.hashCode());
		result = prime * result + ((dNonce == null) ? 0 : dNonce.hashCode());
		result = prime * result + ((eCommitment == null) ? 0 : eCommitment.hashCode());
		result = prime * result + ((eNonce == null) ? 0 : eNonce.hashCode());
		result = prime * result + participantIndex;
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
		if (dCommitment == null) {
			if (other.dCommitment != null)
				return false;
		} else if (!dCommitment.equals(other.dCommitment))
			return false;
		if (dNonce == null) {
			if (other.dNonce != null)
				return false;
		} else if (!dNonce.equals(other.dNonce))
			return false;
		if (eCommitment == null) {
			if (other.eCommitment != null)
				return false;
		} else if (!eCommitment.equals(other.eCommitment))
			return false;
		if (eNonce == null) {
			if (other.eNonce != null)
				return false;
		} else if (!eNonce.equals(other.eNonce))
			return false;
		if (participantIndex != other.participantIndex)
			return false;
		return true;
	}

	@Override
	public String toString() {
		return "NonceCommitment [participantIndex=" + participantIndex + ", dNonce=" + dNonce + ", eNonce=" + eNonce
				+ ", dCommitment=" + dCommitment + ", eCommitment=" + eCommitment + "]";
	}

}
