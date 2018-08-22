/*
 * Copyright (c) IBM Corporation 2018. All Rights Reserved.
 * Project name: pross
 * This project is licensed under the MIT License, see LICENSE.
 */

package com.ibm.pross.common.util.shamir;

import java.io.Serializable;
import java.math.BigInteger;

/**
 * Represents a discrete two-dimensional coordinate on a plane
 */
public class ShamirShare implements Serializable, Comparable<ShamirShare> {

	private static final long serialVersionUID = 1816296249256459664L;

	// The "index" of this point on the x-coordinate
	private final BigInteger x;

	// The secret value of this shareholder's share
	private final BigInteger y;

	public ShamirShare(final BigInteger x, final BigInteger y) {
		this.x = x;
		this.y = y;
	}

	public BigInteger getX() {
		return x;
	}

	public BigInteger getY() {
		return y;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((x == null) ? 0 : x.hashCode());
		result = prime * result + ((y == null) ? 0 : y.hashCode());
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
		ShamirShare other = (ShamirShare) obj;
		if (x == null) {
			if (other.x != null)
				return false;
		} else if (!x.equals(other.x))
			return false;
		if (y == null) {
			if (other.y != null)
				return false;
		} else if (!y.equals(other.y))
			return false;
		return true;
	}

	@Override
	public String toString() {
		return "ShamirShare [x=" + x + ", y=" + y + "]";
	}

	@Override
	public int compareTo(final ShamirShare other) {
		int xComparison = this.getX().compareTo(other.getX());
		if (xComparison == 0) {
			return this.getY().compareTo(other.getY());
		} else {
			return xComparison;
		}
	}

}
