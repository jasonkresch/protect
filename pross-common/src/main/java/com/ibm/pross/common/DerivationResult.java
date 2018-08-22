/*
 * Copyright (c) IBM Corporation 2018. All Rights Reserved.
 * Project name: pross
 * This project is licensed under the MIT License, see LICENSE.
 */

package com.ibm.pross.common;

import java.math.BigInteger;

import com.ibm.pross.common.util.crypto.ecc.EcPoint;

/**
 * Represents one of the derived points from the computation of an Elliptic
 * Curve point multiplication
 */
public class DerivationResult {

	// The index of the server that produced this signature tuple
	private final BigInteger index;

	// One of a necessary threshold number of partial oprf outputs which can be
	// combined to recover the OPRF output
	private final EcPoint derivedSharePoint;

	public DerivationResult(final BigInteger index, final EcPoint derivedSharePoint) {
		this.index = index;
		this.derivedSharePoint = derivedSharePoint;
	}

	/**
	 * The X-coordinate corresponding to the share used in the derivation
	 * 
	 * @return
	 */
	public BigInteger getIndex() {
		return this.index;
	}

	/**
	 * The derived point computed with the share as the scalar multiplier
	 * 
	 * @return
	 */
	public EcPoint getDerivedSharePoint() {
		return this.derivedSharePoint;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((index == null) ? 0 : index.hashCode());
		result = prime * result + ((derivedSharePoint == null) ? 0 : derivedSharePoint.hashCode());
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
		DerivationResult other = (DerivationResult) obj;
		if (index == null) {
			if (other.index != null)
				return false;
		} else if (!index.equals(other.index))
			return false;
		if (derivedSharePoint == null) {
			if (other.derivedSharePoint != null)
				return false;
		} else if (!derivedSharePoint.equals(other.derivedSharePoint))
			return false;
		return true;
	}

	@Override
	public String toString() {
		return "DerivationResult [index=" + index + ", derivedSharePoint=" + derivedSharePoint + "]";
	}

}
