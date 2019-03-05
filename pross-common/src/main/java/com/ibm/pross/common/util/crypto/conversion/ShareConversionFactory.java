package com.ibm.pross.common.util.crypto.conversion;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;

import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;

import com.ibm.pross.common.util.crypto.conversion.prf.PrfKey;
import com.ibm.pross.common.util.crypto.conversion.prf.PseudoRandomFunction.PrfAlgorithm;

public class ShareConversionFactory {

	/**
	 * Generates the set of PRF keys to be used by to build share conversions
	 * 
	 * @param n
	 * @param t
	 * 
	 * @return The map of each unique combination of size t out of n, to an
	 *         associated PRF key for that combination
	 * 
	 * @throws NoSuchAlgorithmException
	 *             If the PRF algorithm is not known
	 */
	public static Map<Set<Integer>, PrfKey> generateKeys(final int n, final int t) throws NoSuchAlgorithmException {

		validateParameters(n, t);

		// Create key generator
		final KeyGenerator keyGenerator = KeyGenerator.getInstance("HMACSHA256");
		keyGenerator.init(256);

		// Set security threshold, which is one less than t
		final int securityThreshold = t - 1;

		// Map of all (n choose securityThreshold) keys to generate
		final Map<Set<Integer>, PrfKey> keyMap = new HashMap<>();
		final CombinationGenerator combinationGenerator = new CombinationGenerator(n, securityThreshold);
		while (combinationGenerator.hasMore()) {

			// Generate combination
			final Set<Integer> combination = combinationGenerator.getNext();

			// Generate a unique PRF key to associate with this combination
			final PrfKey key = new PrfKey(keyGenerator.generateKey());

			// Store combination with the key
			keyMap.put(combination, key);
		}

		return keyMap;
	}

	/**
	 * Creates a list of initialized share conversions which can generate shares
	 * on the fly using a PRF
	 * 
	 * @param n
	 *            The number of share holders in the system (each one holding
	 *            one ShareConversion object)
	 * @param t
	 *            The recovery threshold (how many shares are necessary to
	 *            interpolate the polynomial)
	 * 
	 * @return A list of share conversion instances of size n
	 * 
	 * @throws NoSuchAlgorithmException
	 *             If the PRF algorithm is not known
	 * @throws InvalidAlgorithmParameterException 
	 * @throws NoSuchPaddingException 
	 * @throws InvalidKeyException 
	 */
	public static List<ShareConversion> createShareConversions(final int n, final int t, final PrfAlgorithm prfAlgorithm)
			throws NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, InvalidAlgorithmParameterException {

		validateParameters(n, t);
		
		// Generate the keys
		final Map<Set<Integer>, PrfKey> keyMap = generateKeys(n, t);

		return createShareConversionsWithKeys(n, t, keyMap, prfAlgorithm);
	}

	/**
	 * Creates a list of initialized share conversions which can generate shares
	 * on the fly using a PRF
	 * 
	 * @param n
	 *            The number of share holders in the system (each one holding
	 *            one ShareConversion object)
	 * @param t
	 *            The recovery threshold (how many shares are necessary to
	 *            interpolate the polynomial)
	 * 
	 * @return A list of share conversion instances of size n
	 * @throws InvalidAlgorithmParameterException 
	 * @throws NoSuchPaddingException 
	 * @throws NoSuchAlgorithmException 
	 * @throws InvalidKeyException 
	 */
	public static List<ShareConversion> createShareConversionsWithKeys(final int n, final int t,
			final Map<Set<Integer>, PrfKey> keyMap, final PrfAlgorithm prfAlgorithm) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException {

		validateParameters(n, t);
		
		// Subsets of the PRF keys given to each shareholder
		final List<Map<Set<Integer>, PrfKey>> partitionedKeySets = new ArrayList<>();
		for (int i = 0; i < n; i++) {
			partitionedKeySets.add(new HashMap<Set<Integer>, PrfKey>());
		}

		for (final Entry<Set<Integer>, PrfKey> entry : keyMap.entrySet()) {

			// Get the combination->key association
			final Set<Integer> combination = entry.getKey();
			final PrfKey key = entry.getValue();

			// Provision this combination and key only to the shareholders not
			// in the set
			for (int i = 0; i < n; i++) {
				if (!combination.contains(i)) {
					partitionedKeySets.get(i).put(combination, key);
				}
			}
		}

		// Create share conversions for each shareholder
		final List<ShareConversion> shareConversions = new ArrayList<>();
		for (int i = 0; i < n; i++) {
			final ShareConversion shareConversion = new ShareConversion(partitionedKeySets.get(i), i, prfAlgorithm);
			shareConversions.add(shareConversion);
		}
		return shareConversions;
	}

	private static void validateParameters(final int n, final int t) {
		if (n < t) {
			throw new IllegalArgumentException("n must be greater than or equal to t");
		}
		if (t < 1) {
			throw new IllegalArgumentException("t must be positive");
		}
	}

}
