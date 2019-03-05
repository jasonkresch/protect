
package com.ibm.pross.common.util.crypto.conversion;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;

/**
 * Generates every combination of (n choose r)
 * 
 * Based on algorithm given by Rosen (p. 286)
 */
public class CombinationGenerator {

	// Holds the current state of the permutation
	private final ArrayList<Integer> state;
	
	// Parameters of the combination
	private final int n;
	private final int r;
	
	// For tracking progress through iteration
	private long numLeft;
	private final long total;

	/**
	 * Generates every combination of (n choose r)
	 * 
	 * This object should not be shared between threads.
	 * 
	 * @param n
	 *            The total number of elements
	 * @param r
	 *            The size of the subsets
	 */
	public CombinationGenerator(final int n, final int r) {
		if (r > n) {
			throw new IllegalArgumentException();
		}
		if (n < 1) {
			throw new IllegalArgumentException();
		}
		this.n = n;
		this.r = r;
		this.state = new ArrayList<>(Arrays.asList(new Integer[r]));

		final BigInteger nFact = factorial(n);
		final BigInteger rFact = factorial(r);
		final BigInteger nminusrFact = factorial(n - r);
		this.total = nFact.divide(rFact.multiply(nminusrFact)).longValue();

		reset();
	}

	/**
	 * Starts iteration over the combinations from the beginning
	 */
	public void reset() {
		for (int i = 0; i < this.state.size(); i++) {
			this.state.set(i, i);
		}
		this.numLeft = this.total;
	}

	/**
	 * Returns the number of combinations remaining to be returned
	 * 
	 * @return
	 */
	public long getNumLeft() {
		return this.numLeft;
	}

	/**
	 * Returns true if the iteration over the combinations is incomplete
	 * 
	 * @return
	 */
	public boolean hasMore() {
		return this.numLeft > 0;
	}

	/**
	 * Returns the total number of combinations
	 * 
	 * Equal to (n choose r) = n! / (r! * (n-r)!)
	 * 
	 * @return
	 */
	public long getTotal() {
		return this.total;
	}

	/**
	 * Computes factorial iteratively
	 * 
	 * @param n
	 * @return n!
	 */
	private static BigInteger factorial(final int n) {
		BigInteger fact = BigInteger.ONE;
		for (int i = n; i > 1; i--) {
			fact = fact.multiply(BigInteger.valueOf(i));
		}
		return fact;
	}

	/**
	 * Returns a set of Integers of size r, whose elements are unique and in the
	 * range (0 to (n-1)).
	 * 
	 * @return The next combination, among the set of combinations
	 */
	public Set<Integer> getNext() {

		if (this.numLeft == this.total) {
			// First time iterating through, nothing to do
			this.numLeft--;
		} else if (hasMore()) {
			int i = this.r - 1;
			while (this.state.get(i) == (this.n - this.r + i)) {
				i--;
			}
			this.state.set(i, this.state.get(i) + 1);
			for (int j = i + 1; j < this.r; j++) {
				this.state.set(j, this.state.get(i) + j - i);
			}
			this.numLeft--;
		} else {
			throw new IllegalStateException("No more combinations to return!");
		}

		return createSetFromArray(this.state);
	}

	private static Set<Integer> createSetFromArray(List<Integer> list) {
		// Create a copy, and make it unmodifiable
		return Collections.unmodifiableSet(new TreeSet<Integer>(list));
	}

}
