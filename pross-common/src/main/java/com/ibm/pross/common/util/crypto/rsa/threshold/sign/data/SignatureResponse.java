package com.ibm.pross.common.util.crypto.rsa.threshold.sign.data;

import java.math.BigInteger;

/**
 * Represents the response from a server for a signature share request. It
 * consists of two parts:
 * 
 * <pre>
 * 1. Signature Share - a share which can be combined with
 *                      a threshold number of like signature
 *                      shares to yield a signature
 * 2. Signature Share Proof - verification information which
 *                            asserts that the Signature Share
 *                            was computed correctly
 * </pre>
 */
public class SignatureResponse {

	// The index of the server that produced this signature tuple
	private final BigInteger serverIndex;

	// A share of a signature computed by a server, a threshold of which may be
	// combined to recover the signature
	private final BigInteger signatureShare;

	// A "proof" which can be used to verify the consistency of the share
	private final SignatureShareProof signatureShareProof;

	public SignatureResponse(final BigInteger serverIndex, final BigInteger signatureShare,
			final SignatureShareProof signatureShareProof) {
		this.serverIndex = serverIndex;
		this.signatureShare = signatureShare;
		this.signatureShareProof = signatureShareProof;
	}

	/**
	 * X-coordinate represented by this server
	 * 
	 * @return
	 */
	public BigInteger getServerIndex() {
		return this.serverIndex;
	}

	/**
	 * Signature share computed by this server for a given message
	 * 
	 * @return
	 */
	public BigInteger getSignatureShare() {
		return this.signatureShare;
	}

	/**
	 * Signature Share Proof to assert the correctness of the Signature Share
	 * 
	 * @return
	 */
	public SignatureShareProof getSignatureShareProof() {
		return this.signatureShareProof;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((serverIndex == null) ? 0 : serverIndex.hashCode());
		result = prime * result + ((signatureShare == null) ? 0 : signatureShare.hashCode());
		result = prime * result + ((signatureShareProof == null) ? 0 : signatureShareProof.hashCode());
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
		SignatureResponse other = (SignatureResponse) obj;
		if (serverIndex == null) {
			if (other.serverIndex != null)
				return false;
		} else if (!serverIndex.equals(other.serverIndex))
			return false;
		if (signatureShare == null) {
			if (other.signatureShare != null)
				return false;
		} else if (!signatureShare.equals(other.signatureShare))
			return false;
		if (signatureShareProof == null) {
			if (other.signatureShareProof != null)
				return false;
		} else if (!signatureShareProof.equals(other.signatureShareProof))
			return false;
		return true;
	}

	

}
