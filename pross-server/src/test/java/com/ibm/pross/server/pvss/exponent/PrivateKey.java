package com.ibm.pross.server.pvss.exponent;

import java.math.BigInteger;

public class PrivateKey {

	private final BigInteger x;

	public PrivateKey(final BigInteger x) {
		this.x = x;
	}

	public BigInteger getX() {
		return x;
	}

}
