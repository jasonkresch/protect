/*
 * Copyright (c) IBM Corporation 2018. All Rights Reserved.
 * Project name: pross
 * This project is licensed under the MIT License, see LICENSE.
 */

package com.ibm.pross.client.prf;

import com.ibm.pross.common.EcPseudoRandomFunction;

/**
 * This class implements convinence methods for properly constructing
 * derivations to support thresholding, robustness (proxy layer verifiability),
 * client-side obliviousness, and client-side verifiability of results.
 */
public class DerivationFactory {

	/**
	 * This method adds verifiability to each interaction with a shareholder,
	 * for example, to create a robust proxy layer that can detect malfunctions
	 * of individual shareholders.
	 * 
	 * Warning: this does not provide or implement any obliviousness, and must
	 * not be used by clients that need security for their inputs or outputs. It
	 * should only be used by intermediate "proxy" layers that provide threshold
	 * functionality for clients that want to create the operation as a single
	 * interaction with one entity.
	 * 
	 * @param shareholders
	 *            A set of unverified shareholders
	 * @param threshold
	 *            The minimum threshold for performing the derivation
	 * @return A threshold derivation that can detect and exclude malfunctioning
	 *         shareholders
	 */
	public static ThresholdDerivation createRobustThresholdDerivation(final EcPseudoRandomFunction[] shareholders,
			final int threshold) {

		final VerifiedDerivation[] verifiedDerivations = new VerifiedDerivation[shareholders.length];
		for (int i = 0; i < shareholders.length; i++) {
			EcPseudoRandomFunction unverifiedDerivation = shareholders[i];
			verifiedDerivations[i] = new VerifiedDerivation(unverifiedDerivation, unverifiedDerivation);
		}

		// Create derivation based on a threshold of (now verified) shareholders
		final ThresholdDerivation thresholdDerivation = new ThresholdDerivation(verifiedDerivations, threshold);

		return thresholdDerivation;
	}

	/**
	 * This method returns a robust threshold configuration with client-side
	 * obliviousness.
	 * 
	 * Warning: This method does not support client-side verifiability, and is
	 * subject to a malfunctioning proxy layer. That is, errors created by the
	 * "robustThresholdDerivation" will not be detected.
	 * 
	 * @param shareholders
	 *            A set of unverified shareholders
	 * @param threshold
	 *            The minimum threshold for performing the derivation
	 * @return A threshold derivation that can detect and exclude malfunctioning
	 *         shareholders and provides obliviousness for the client
	 */
	public static EcPseudoRandomFunction createObliviousRobustThresholdDerivation(final EcPseudoRandomFunction[] shareholders,
			final int threshold) {

		// Create robust derivation based on a threshold of shareholders
		final ThresholdDerivation robustThresholdDerivation = createRobustThresholdDerivation(shareholders, threshold);

		// Wrap the threshold derivation with an oblivious derivation
		final ObliviousDerivation obliviousThresholdDerivation = new ObliviousDerivation(robustThresholdDerivation);

		return obliviousThresholdDerivation;
	}

	/**
	 * This method returns a robust threshold configuration with client-side
	 * obliviousness and client-side verification of results. This method has
	 * twice the cost of the non-verifiable method.
	 * 
	 * @param shareholders
	 *            A set of unverified shareholders
	 * @param threshold
	 *            The minimum threshold for performing the derivation
	 * @return A threshold derivation that can detect and exclude malfunctioning
	 *         shareholders and provides obliviousness and verifiability for the
	 *         client
	 */
	public static EcPseudoRandomFunction createVerifiedObliviousRobustThresholdDerivation(final EcPseudoRandomFunction[] shareholders,
			final int threshold) {

		// Create robust derivation based on a threshold of shareholders
		final ThresholdDerivation robustThresholdDerivation = createRobustThresholdDerivation(shareholders, threshold);

		// Wrap the threshold derivation with an oblivious derivation
		final ObliviousDerivation obliviousThresholdDerivation = new ObliviousDerivation(robustThresholdDerivation);

		// Create a verified derivation using the oblivious derivation to get
		// the result, and the non-oblivious derivation to get the challenge
		// responses
		final VerifiedDerivation verifiedObliviousThresholdDerivation = new VerifiedDerivation(
				obliviousThresholdDerivation, robustThresholdDerivation);

		return verifiedObliviousThresholdDerivation;
	}
}
