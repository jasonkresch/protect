package com.ibm.pross.common.util.crypto.conversion;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.AbstractMap.SimpleEntry;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;

import javax.crypto.NoSuchPaddingException;

import com.ibm.pross.common.CommonConfiguration;
import com.ibm.pross.common.util.crypto.conversion.prf.PrfKey;
import com.ibm.pross.common.util.crypto.conversion.prf.PseudoRandomFunction;
import com.ibm.pross.common.util.crypto.conversion.prf.PseudoRandomFunction.PrfAlgorithm;
import com.ibm.pross.common.util.crypto.ecc.EcCurve;
import com.ibm.pross.common.util.shamir.ShamirShare;

public class ShareConversion {

	// Static fields
	final public static EcCurve curve = CommonConfiguration.CURVE;
	final public static BigInteger r = curve.getR();

	// This is a list of products generated during construction by interpolating
	// the shareholder index for each threshold subset. These are cached and
	// used to generate shares.
	// The corresponding secret key is mapped to each product
	private final List<SimpleEntry<BigInteger, PseudoRandomFunction>> productPairs;

	private final int shareholderXCoordinate;

	/**
	 * Creates a ShareConversion instance for a given shareholder, based on a
	 * map of unique combinations to PRF keys
	 * 
	 * @param partitionedKeySet
	 *            Set of PRF keys for this shareholder
	 * @param shareholderIndex
	 *            The index of the shareholder (one less than the x-coordinate
	 *            of it's ShamirShare)
	 * @param prfAlgorithm
	 * 	The type of PRF to use to generate shares
	 * 
	 * @throws InvalidKeyException
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws InvalidAlgorithmParameterException
	 */
	public ShareConversion(final Map<Set<Integer>, PrfKey> partitionedKeySet, final int shareholderIndex, final PrfAlgorithm prfAlgorithm)
			throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException,
			InvalidAlgorithmParameterException {
		this.shareholderXCoordinate = shareholderIndex + 1;

		// Note: shareholder index is one less than the shareholder's share's
		// x-coordinate
		//final ShamirShare interceptShare = new ShamirShare(BigInteger.ZERO, BigInteger.ONE);

		this.productPairs = new ArrayList<>();
		for (final Entry<Set<Integer>, PrfKey> entry : partitionedKeySet.entrySet()) {

			// Get values from this entry
			final Set<Integer> shareholderIndices = entry.getKey();

			final BigInteger y = computeFactor(createJSetFromIndices(shareholderIndices), this.shareholderXCoordinate);

			// Cache the y-value and associate it with its initialized PRF
			final PrfKey prfKey = entry.getValue();
			final PseudoRandomFunction prf = PseudoRandomFunction.create(prfAlgorithm, prfKey);
			this.productPairs.add(new SimpleEntry<BigInteger, PseudoRandomFunction>(y, prf));
		}
	}

	private static BigInteger[] createJSetFromIndices(final Set<Integer> indices) {
		final BigInteger[] jSet = new BigInteger[indices.size()];
		int i = 0;
		for (Integer index : indices) {
			jSet[i++] = BigInteger.valueOf(index + 1);
		}
		return jSet;
	}

	private static BigInteger computeFactor(final BigInteger[] otherIndices, final int shareholderIndex) {

		final BigInteger i = BigInteger.valueOf(shareholderIndex);

		BigInteger numerator = BigInteger.ONE;
		BigInteger denominator = BigInteger.ONE;

		for (final BigInteger j : otherIndices) {
			numerator = numerator.multiply(i.subtract(j)).mod(r);
			denominator = denominator.multiply(j.negate()).mod(r);
		}

		final BigInteger invDenominator = denominator.modInverse(r);
		return numerator.multiply(invDenominator).mod(r);
	}

	// Generates a unique share for the given input, for all shareholders given
	// the same input the shares will be consistent
	public ShamirShare generateShamirShare(final byte[] input) {

		BigInteger sum = BigInteger.ZERO;

		for (final Entry<BigInteger, PseudoRandomFunction> entry : this.productPairs) {
			// Get values from this entry
			final BigInteger yCoordinate = entry.getKey();
			final PseudoRandomFunction prf = entry.getValue();

			// Apply PRF key to the input
			final byte[] prfOutput = prf.computePrf(input);
			final BigInteger result = new BigInteger(1, prfOutput);

			// Combine the PRF output with the y coordinate
			final BigInteger product = yCoordinate.multiply(result).mod(r);

			// Keep a running sum of all products
			sum = sum.add(product).mod(r);
		}

		// Produce a share based on the final sum
		return new ShamirShare(BigInteger.valueOf(this.shareholderXCoordinate), sum);
	}

}
