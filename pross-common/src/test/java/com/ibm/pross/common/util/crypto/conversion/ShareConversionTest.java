package com.ibm.pross.common.util.crypto.conversion;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.junit.Assert;
import org.junit.Test;

import com.ibm.pross.common.config.CommonConfiguration;
import com.ibm.pross.common.util.crypto.conversion.prf.PrfKey;
import com.ibm.pross.common.util.crypto.conversion.prf.PseudoRandomFunction;
import com.ibm.pross.common.util.crypto.conversion.prf.PseudoRandomFunction.PrfAlgorithm;
import com.ibm.pross.common.util.crypto.ecc.EcCurve;
import com.ibm.pross.common.util.shamir.Polynomials;
import com.ibm.pross.common.util.shamir.ShamirShare;

public class ShareConversionTest {

	// Static fields
	final public static EcCurve curve = CommonConfiguration.CURVE;
	final public static BigInteger r = curve.getR();

	final protected static byte[] SHORT_MESSAGE_1 = "The quick brown fox ".getBytes(StandardCharsets.UTF_8);
	final protected static byte[] SHORT_MESSAGE_2 = "jumps over the lazy dog.".getBytes(StandardCharsets.UTF_8);
	final protected static byte[] LONG_MESSAGE_1 = new byte[4097];
	final protected static byte[] LONG_MESSAGE_2;
	final protected static byte[] LONGER_MESSAGE_1;
	static {
		Arrays.fill(LONG_MESSAGE_1, (byte) 0x19);

		// Flip last bit for message 2
		LONG_MESSAGE_2 = LONG_MESSAGE_1.clone();
		LONG_MESSAGE_2[LONG_MESSAGE_2.length - 1] = (byte) (LONG_MESSAGE_2[LONG_MESSAGE_2.length - 1] ^ 1);

		// Make this message 1 byte longer
		LONGER_MESSAGE_1 = new byte[LONG_MESSAGE_1.length + 1];
		Arrays.fill(LONGER_MESSAGE_1, (byte) 0x19);
	}

	// Ensure we get valid shares using given PRF and input (verify every
	// combination of shares decodes correctly)
	protected List<ShamirShare> testGenerateShamirShareHmacAllDecodeCombinations(final int n, final int t,
			final PrfAlgorithm prfAlgorithm, final byte[] input) throws Exception {

		// Create keys to be used for share conversion
		final Map<Set<Integer>, PrfKey> keyMap = ShareConversionFactory.generateKeys(n, t);

		return testGenerateShamirShareHmacAllDecodeCombinations(keyMap, n, t, prfAlgorithm, input);
	}

	// Ensure we get valid shares using given PRF and input (verify every
	// combination of shares decodes correctly)
	protected List<ShamirShare> testGenerateShamirShareHmacAllDecodeCombinations(final Map<Set<Integer>, PrfKey> keyMap,
			final int n, final int t, final PrfAlgorithm prfAlgorithm, final byte[] input) throws Exception {

		// Determine expected prf sum for the given input message
		final BigInteger secret = computePrfOutputSum(prfAlgorithm, keyMap, input);

		// Create share conversions for each shareholder
		final List<ShareConversion> shareConversions = ShareConversionFactory.createShareConversionsWithKeys(n, t,
				keyMap, prfAlgorithm);

		// Create shares from the input message
		final List<ShamirShare> allShares = new ArrayList<>();
		for (final ShareConversion conversion : shareConversions) {
			allShares.add(conversion.generateShamirShare(input));
		}
		Assert.assertEquals(n, new HashSet<>(allShares).size());

		// Apply every combination of t and n to decode
		final CombinationGenerator combinationGenerator = new CombinationGenerator(n, t);
		while (combinationGenerator.hasMore()) {
			final Set<Integer> combination = combinationGenerator.getNext();
			final List<ShamirShare> subset = createSubset(allShares, combination);
			final BigInteger recoveredSecret = Polynomials.interpolateComplete(subset, t, 0);
			Assert.assertEquals("Invalid share computed for combination: " + combination, secret, recoveredSecret);
		}

		return allShares;
	}

	@Test
	public void testGenerateShamirShareHmacAllDecodeCombinationsSmallTandN() throws Exception {
		testGenerateShamirShareHmacAllDecodeCombinations(5, 2, PrfAlgorithm.HMAC, SHORT_MESSAGE_1);
	}

	@Test
	public void testGenerateShamirShareAesAllDecodeCombinationsSmallTandN() throws Exception {
		testGenerateShamirShareHmacAllDecodeCombinations(5, 2, PrfAlgorithm.AES, SHORT_MESSAGE_1);
	}

	@Test
	public void testGenerateShamirShareHmacAllDecodeCombinationsSmallTandLargeN() throws Exception {
		testGenerateShamirShareHmacAllDecodeCombinations(40, 3, PrfAlgorithm.HMAC, SHORT_MESSAGE_1);
	}

	@Test
	public void testGenerateShamirShareAesAllDecodeCombinationsSmallTandLargeN() throws Exception {
		testGenerateShamirShareHmacAllDecodeCombinations(40, 3, PrfAlgorithm.AES, SHORT_MESSAGE_1);
	}

	@Test
	public void testGenerateShamirShareHmacAllDecodeCombinationsLargeTandLargeN() throws Exception {
		testGenerateShamirShareHmacAllDecodeCombinations(15, 12, PrfAlgorithm.HMAC, SHORT_MESSAGE_1);
	}

	@Test
	public void testGenerateShamirShareAesAllDecodeCombinationsLargeTandLargeN() throws Exception {
		testGenerateShamirShareHmacAllDecodeCombinations(15, 12, PrfAlgorithm.AES, SHORT_MESSAGE_1);
	}

	// Try various N and T combinations
	protected void testShareConversionVariousConfigurations(final PrfAlgorithm prfAlgorithm, final byte[][] inputs)
			throws Exception {

		for (int t = 1; t < 10; t++) {
			for (int n = t; n < 10; n++) {

				// Create keys to be used for share conversion
				final Map<Set<Integer>, PrfKey> keyMap = ShareConversionFactory.generateKeys(n, t);

				// Create share conversions for each shareholder
				final List<ShareConversion> shareConversions = ShareConversionFactory.createShareConversionsWithKeys(n,
						t, keyMap, prfAlgorithm);

				for (byte[] input : inputs) {
					// Determine expected prf sum for the given input
					// message
					final BigInteger secret = computePrfOutputSum(prfAlgorithm, keyMap, input);

					// Create shares from the input message
					final List<ShamirShare> allShares = new ArrayList<>();
					for (final ShareConversion conversion : shareConversions) {
						allShares.add(conversion.generateShamirShare(input));
					}

					// Try processing each input 10 times with a random set of
					// shares
					for (int i = 0; i < 10; i++) {
						final List<ShamirShare> subset = getRandomSubset(allShares, t);			
						final BigInteger recoveredSecret = Polynomials.interpolateComplete(subset, t, 0);
						Assert.assertEquals("Invalid share computed for combination: " + subset, secret,
								recoveredSecret);

					}
				}
			}
		}
	}

	@Test
	public void testShareConversionVariousConfigurationsAes() throws Exception {
		testShareConversionVariousConfigurations(PrfAlgorithm.AES,
				new byte[][] { SHORT_MESSAGE_1, SHORT_MESSAGE_2, LONG_MESSAGE_1, LONG_MESSAGE_2, LONGER_MESSAGE_1 });
	}

	@Test
	public void testShareConversionVariousConfigurationsHmac() throws Exception {
		testShareConversionVariousConfigurations(PrfAlgorithm.HMAC,
				new byte[][] { SHORT_MESSAGE_1, SHORT_MESSAGE_2, LONG_MESSAGE_1, LONG_MESSAGE_2, LONGER_MESSAGE_1 });
	}

	protected void testShamirShareConsistencySameMessage(final PrfAlgorithm prfAlgorithm, final byte[] message)
			throws Exception {

		int n = 7;
		int t = 4;

		// Create keys to be used for share conversion
		final Map<Set<Integer>, PrfKey> keyMap = ShareConversionFactory.generateKeys(n, t);

		final List<ShamirShare> shares1 = testGenerateShamirShareHmacAllDecodeCombinations(keyMap, n, t, prfAlgorithm,
				message);
		final List<ShamirShare> shares2 = testGenerateShamirShareHmacAllDecodeCombinations(keyMap, n, t, prfAlgorithm,
				message);
		Assert.assertEquals("Inconsistent set of shares generated for same message", shares1, shares2);
	}

	@Test
	public void testShamirShareHmacConsistencyVariousMessages() throws Exception {
		final PrfAlgorithm prfAlgorithm = PrfAlgorithm.HMAC;
		testShamirShareConsistencySameMessage(prfAlgorithm, SHORT_MESSAGE_1);
		testShamirShareConsistencySameMessage(prfAlgorithm, SHORT_MESSAGE_2);
		testShamirShareConsistencySameMessage(prfAlgorithm, LONG_MESSAGE_1);
		testShamirShareConsistencySameMessage(prfAlgorithm, LONG_MESSAGE_2);
		testShamirShareConsistencySameMessage(prfAlgorithm, LONGER_MESSAGE_1);
	}

	@Test
	public void testShamirShareAesConsistencyVariousMessages() throws Exception {
		final PrfAlgorithm prfAlgorithm = PrfAlgorithm.AES;
		testShamirShareConsistencySameMessage(prfAlgorithm, SHORT_MESSAGE_1);
		testShamirShareConsistencySameMessage(prfAlgorithm, SHORT_MESSAGE_2);
		testShamirShareConsistencySameMessage(prfAlgorithm, LONG_MESSAGE_1);
		testShamirShareConsistencySameMessage(prfAlgorithm, LONG_MESSAGE_2);
		testShamirShareConsistencySameMessage(prfAlgorithm, LONGER_MESSAGE_1);
	}

	protected void testShamirSharDifferentSharesDifferentMessage(final PrfAlgorithm prfAlgorithm,
			final byte[][] messages) throws Exception {

		int n = 7;
		int t = 4;

		// Create keys to be used for share conversion
		final Map<Set<Integer>, PrfKey> keyMap = ShareConversionFactory.generateKeys(n, t);

		final Set<List<ShamirShare>> uniqueShareLists = new HashSet<>();
		for (int i = 0; i < messages.length; i++) {
			final byte[] message = messages[i];
			final List<ShamirShare> shares = testGenerateShamirShareHmacAllDecodeCombinations(keyMap, n, t,
					prfAlgorithm, message);
			uniqueShareLists.add(shares);
			if (uniqueShareLists.size() != (i + 1)) {
				Assert.fail("Message at index " + i + " did not produce a unique set of shares");
			}
		}
	}

	@Test
	public void testGenerateShamirShareHmacDifferentInputs() throws Exception {
		testShamirSharDifferentSharesDifferentMessage(PrfAlgorithm.HMAC,
				new byte[][] { SHORT_MESSAGE_1, SHORT_MESSAGE_2, LONG_MESSAGE_1, LONG_MESSAGE_2, LONGER_MESSAGE_1 });
	}

	@Test
	public void testGenerateShamirShareAesDifferentInputs() throws Exception {
		testShamirSharDifferentSharesDifferentMessage(PrfAlgorithm.AES,
				new byte[][] { SHORT_MESSAGE_1, SHORT_MESSAGE_2, LONG_MESSAGE_1, LONG_MESSAGE_2, LONGER_MESSAGE_1 });
	}

	protected void testShamirSharDifferentSharesDifferentMessage(final PrfAlgorithm[] prfAlgorithms,
			final byte[][] messages) throws Exception {

		int n = 7;
		int t = 4;

		// Create keys to be used for share conversion
		final Map<Set<Integer>, PrfKey> keyMap = ShareConversionFactory.generateKeys(n, t);

		for (byte[] message : messages) {

			final Set<List<ShamirShare>> uniqueShareLists = new HashSet<>();
			int i = 0;
			for (PrfAlgorithm prfAlgorithm : prfAlgorithms) {
				i++;
				final List<ShamirShare> shares = testGenerateShamirShareHmacAllDecodeCombinations(keyMap, n, t,
						prfAlgorithm, message);
				uniqueShareLists.add(shares);
				if (uniqueShareLists.size() != i) {
					Assert.fail("PRF at index " + i + " did not produce a unique set of shares");
				}
			}
		}
	}

	@Test
	public void testGenerateShamirShareDifferentPrfsSameInputs() throws Exception {
		testShamirSharDifferentSharesDifferentMessage(new PrfAlgorithm[] { PrfAlgorithm.AES, PrfAlgorithm.HMAC },
				new byte[][] { SHORT_MESSAGE_1, SHORT_MESSAGE_2, LONG_MESSAGE_1, LONG_MESSAGE_2, LONGER_MESSAGE_1 });
	}

	/************************************************************************************************************/
	/** 											Static methods
	/************************************************************************************************************/

	// Generates a random subset from all the shares
	private static List<ShamirShare> getRandomSubset(final List<ShamirShare> allShares, final int threshold) {

		// Create copy so we don't change what was passed in
		final List<ShamirShare> copy = new ArrayList<>(allShares);

		// Randomize list
		Collections.shuffle(copy);

		// Create a subset
		final List<ShamirShare> subset = new ArrayList<>();
		for (int i = 0; i < threshold; i++) {
			subset.add(copy.get(i));
		}
		Collections.sort(subset);

		return subset;
	}

	// Generates a subset of shares for a given combination
	private static List<ShamirShare> createSubset(final List<ShamirShare> allShares, Set<Integer> indicesToRetain) {

		// Create a subset
		final List<ShamirShare> subset = new ArrayList<>();
		for (final ShamirShare share : allShares) {
			if (indicesToRetain.contains(share.getX().intValue() - 1)) {
				subset.add(share);
			}
		}
		Collections.sort(subset);

		return subset;
	}

	private static BigInteger computePrfOutputSum(final PrfAlgorithm prfAlgorithm,
			final Map<Set<Integer>, PrfKey> keyMap, final byte[] input) throws Exception {
		BigInteger sum = BigInteger.ZERO;
		for (final PrfKey prfKey : keyMap.values()) {
			final PseudoRandomFunction prf = PseudoRandomFunction.create(prfAlgorithm, prfKey);
			final byte[] prfOutput = prf.computePrf(input);
			final BigInteger result = new BigInteger(1, prfOutput);
			sum = sum.add(result).mod(r);
		}
		return sum;
	}
}
