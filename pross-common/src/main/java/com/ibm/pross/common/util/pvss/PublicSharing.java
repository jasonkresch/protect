package com.ibm.pross.common.util.pvss;

import java.io.Serializable;
import java.math.BigInteger;
import java.util.Arrays;

import com.ibm.pross.common.util.crypto.ecc.EcPoint;
import com.ibm.pross.common.util.crypto.paillier.PaillierCipher;
import com.ibm.pross.common.util.crypto.paillier.PaillierPrivateKey;
import com.ibm.pross.common.util.crypto.paillier.PaillierPublicKey;
import com.ibm.pross.common.util.crypto.zkp.pedersen.PedersenEqRangeProof;
import com.ibm.pross.common.util.crypto.zkp.pedersen.PedersenEqRangeProofVerifier;
import com.ibm.pross.common.util.shamir.ShamirShare;

/**
 * Represents a Publicly Verifiable Secret Sharing (PVSS)
 * 
 * The sharing can be verified as correct by anyone who knows the public keys of
 * the shareholders.
 * 
 * The sharing is comprised of three parts: - The Pedersen commitments of which
 * there are t
 * 
 * @author jresch
 *
 */
public class PublicSharing implements Serializable {

	private static final long serialVersionUID = -7866009350143080725L;
	
	// Contains encrypted shares (for polynomial 1 & 2)
	// Contains Pedersen commitments
	// Contains zero knowledge proofs for each (share/commitment)
	
	private final EcPoint[] pedersenCommitments;
	private final BigInteger[] encryptedShares1;
	private final BigInteger[] encryptedShares2;
	private final PedersenEqRangeProof[] proofs;

	private final int numShares;
	private final int threshold;

	/**
	 * Constructs a public sharing of a secret. This sharing can be validated by
	 * anyone who holds the public keys of the shareholding participants.
	 * 
	 * @param pedersenCommitments
	 * @param encryptedShares
	 * @param proofs
	 */
	public PublicSharing(final EcPoint[] pedersenCommitments, final BigInteger[] encryptedShares1,
			final BigInteger[] encryptedShares2, final PedersenEqRangeProof[] proofs) {

		// Determine n and t from the inputs
		this.numShares = encryptedShares1.length;
		this.threshold = pedersenCommitments.length;

		// Perform consistency checks
		if (this.threshold > this.numShares) {
			throw new IllegalArgumentException("Threshold must be less than or equal to numShares");
		}
		if (proofs.length != this.numShares) {
			throw new IllegalArgumentException("Number of shares does not match the number of proofs");
		}
		if (encryptedShares2.length != this.numShares) {
			throw new IllegalArgumentException("First number of shares does not match the second number of shares");
		}

		this.pedersenCommitments = pedersenCommitments;
		this.encryptedShares1 = encryptedShares1;
		this.encryptedShares2 = encryptedShares2;
		this.proofs = proofs;
	}

	public EcPoint[] getPedersenCommitments() {
		return pedersenCommitments;
	}

	public BigInteger[] getEncryptedShares1() {
		return encryptedShares1;
	}

	public BigInteger[] getEncryptedShares2() {
		return encryptedShares2;
	}

	public PedersenEqRangeProof[] getProofs() {
		return proofs;
	}

	public int getNumShares() {
		return numShares;
	}

	public int getThreshold() {
		return threshold;
	}

	/**
	 * Verify the sharing is correct
	 * 
	 * @param shareholderKeys
	 *            The ordered array of shareholder public keys
	 * @return True IFF the sharing is valid
	 */
	public boolean verifyAllShares(final PaillierPublicKey[] shareholderKeys) {

		// Make sure each proof can be verified
		for (int i = 0; i < shareholderKeys.length; i++) {
			if (!verifyShare(i, shareholderKeys[i])) {
				return false;
			}
		}

		// Return true only if all proofs were validated
		return true;
	}

	/**
	 * Verify that a particular encrypted share is valid using the zero knowledge
	 * proof and Pedersen commitments.
	 * 
	 * @param shareIndex
	 * @param encryptionKey
	 * @return
	 */
	public boolean verifyShare(final int shareIndex, final PaillierPublicKey encryptionKey) {

		// Get the corresponding share to validate
		final BigInteger encryptedShare1 = this.encryptedShares1[shareIndex];
		final BigInteger encryptedShare2 = this.encryptedShares2[shareIndex];

		// Use the Pedersen commitments to determine g^share_i using polynomial
		// evaluation "in the exponent"
		final BigInteger xPosition = BigInteger.valueOf(shareIndex + 1);
		final EcPoint shareCommitment = PublicSharingGenerator.interpolatePedersonCommitments(xPosition,
				this.pedersenCommitments);

		// Check the proof
		final PedersenEqRangeProof proof = this.proofs[shareIndex];
		return PedersenEqRangeProofVerifier.isValid(proof, encryptedShare1, encryptedShare2, shareCommitment,
				encryptionKey);
	}
	

	/**
	 * Return the Pedersen commitment to the secret that is shared
	 * @return
	 */
	public EcPoint getSecretCommitment() {

		// Use the Pedersen commitments to determine g^secret using polynomial evaluation "in the exponent"
		final BigInteger xPosition = BigInteger.ZERO;
		final EcPoint secretCommitment = PublicSharingGenerator.interpolatePedersonCommitments(xPosition,
				this.pedersenCommitments);

		return secretCommitment;
	}

	/**
	 * Decrypt a first share from the public sharing using the appropriate private key
	 * 
	 * @param shareIndex
	 * @param decryptionKey
	 * @return
	 */
	public ShamirShare accessShare1(final int shareIndex, final PaillierPrivateKey decryptionKey) {
		final BigInteger xPosition = BigInteger.valueOf(shareIndex + 1);
		final BigInteger decryptedY = PaillierCipher.decrypt(decryptionKey, this.encryptedShares1[shareIndex]);
		return new ShamirShare(xPosition, decryptedY);
	}
	
	/**
	 * Decrypt a second share from the public sharing using the appropriate private key
	 * 
	 * @param shareIndex
	 * @param decryptionKey
	 * @return
	 */
	public ShamirShare accessShare2(final int shareIndex, final PaillierPrivateKey decryptionKey) {
		final BigInteger xPosition = BigInteger.valueOf(shareIndex + 1);
		final BigInteger decryptedY = PaillierCipher.decrypt(decryptionKey, this.encryptedShares2[shareIndex]);
		return new ShamirShare(xPosition, decryptedY);
	}

	@Override
	public String toString() {
		return "PublicSharing [pedersenCommitments=" + Arrays.toString(pedersenCommitments) + ", encryptedShares1="
				+ Arrays.toString(encryptedShares1) + ", encryptedShares2=" + Arrays.toString(encryptedShares2)
				+ ", proofs=" + Arrays.toString(proofs) + ", numShares=" + numShares + ", threshold=" + threshold + "]";
	}

	public long getSize() {
		long size = 0;
		for (final EcPoint pedersenCommitment : this.pedersenCommitments) {
			size += pedersenCommitment.getX().toByteArray().length + 1; // Assumes point compression
		}
		for (final BigInteger encryptedShare1 : this.encryptedShares1) {
			size += encryptedShare1.toByteArray().length;
		}
		for (final BigInteger encryptedShare2 : this.encryptedShares2) {
			size += encryptedShare2.toByteArray().length;
		}
		for (final PedersenEqRangeProof proof : this.proofs) {
			size += proof.getSize();
		}
		return size;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + Arrays.hashCode(encryptedShares1);
		result = prime * result + Arrays.hashCode(encryptedShares2);
		result = prime * result + numShares;
		result = prime * result + Arrays.hashCode(pedersenCommitments);
		result = prime * result + Arrays.hashCode(proofs);
		result = prime * result + threshold;
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
		PublicSharing other = (PublicSharing) obj;
		if (!Arrays.equals(encryptedShares1, other.encryptedShares1))
			return false;
		if (!Arrays.equals(encryptedShares2, other.encryptedShares2))
			return false;
		if (numShares != other.numShares)
			return false;
		if (!Arrays.equals(pedersenCommitments, other.pedersenCommitments))
			return false;
		if (!Arrays.equals(proofs, other.proofs))
			return false;
		if (threshold != other.threshold)
			return false;
		return true;
	}

}
