package com.ibm.pross.common.util.crypto.rsa.threshold.sign.server;

import java.math.BigInteger;
import java.util.Arrays;

import com.ibm.pross.common.util.serialization.Parse;

/**
 * All public configuration information concerning the configuration for a
 * particular user of a password-protected threshold secret distribution. This
 * public configuration information is identical across all threshold servers.
 */
public class ServerPublicConfiguration {

	// Number of servers
	private final int serverCount;

	// Threshold needed to sign
	private final int threshold;

	// Public modulus for RSA key pair
	private final BigInteger n;

	// Public exponent for RSA keypair
	private final BigInteger e;

	// Public verification parameter
	private final BigInteger v;

	private final BigInteger[] verificationKeys;

	public ServerPublicConfiguration(int serverCount, int threshold, BigInteger n, BigInteger e, BigInteger v,
			BigInteger[] verificationKeys) {
		this.serverCount = serverCount;
		this.threshold = threshold;
		this.n = n;
		this.e = e;
		this.v = v;
		this.verificationKeys = verificationKeys;
	}

	public int getServerCount() {
		return serverCount;
	}

	public int getThreshold() {
		return threshold;
	}

	public BigInteger getN() {
		return n;
	}

	public BigInteger getE() {
		return e;
	}

	public BigInteger getV() {
		return v;
	}

	public BigInteger[] getVerificationKeys() {
		return verificationKeys;
	}

	@Override
	public String toString() {
		return "ServerPublicConfiguration [serverCount=" + serverCount + ", threshold=" + threshold + ", n=" + n
				+ ", e=" + e + ", v=" + v + ", verificationKeys=" + Arrays.toString(verificationKeys) + "]";
	}

	/**
	 * Generate a "Common Reference String" which is guaranteed to be unique for all
	 * identical instances
	 * 
	 * @return
	 */
	public byte[] getCrs() {
		// Create common reference string representing public parameters of
		// previous configuration
		final BigInteger serverCount = BigInteger.valueOf(this.getServerCount());
		final BigInteger threshold = BigInteger.valueOf(this.getThreshold());
		final BigInteger n = this.getN();
		final BigInteger e = this.getE();
		final BigInteger v = this.getV();
		final BigInteger[] verificationKeys = this.getVerificationKeys();

		final byte[] crs1 = Parse.concatenate(serverCount, threshold, n, e, v);
		final byte[] crs2 = Parse.concatenate(verificationKeys);

		// Common reference string representing all public configuration
		final byte[] crs = Parse.concatenate(crs1, crs2);

		return crs;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((e == null) ? 0 : e.hashCode());
		result = prime * result + ((n == null) ? 0 : n.hashCode());
		result = prime * result + serverCount;
		result = prime * result + threshold;
		result = prime * result + ((v == null) ? 0 : v.hashCode());
		result = prime * result + Arrays.hashCode(verificationKeys);
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
		ServerPublicConfiguration other = (ServerPublicConfiguration) obj;
		if (e == null) {
			if (other.e != null)
				return false;
		} else if (!e.equals(other.e))
			return false;
		if (n == null) {
			if (other.n != null)
				return false;
		} else if (!n.equals(other.n))
			return false;
		if (serverCount != other.serverCount)
			return false;
		if (threshold != other.threshold)
			return false;
		if (v == null) {
			if (other.v != null)
				return false;
		} else if (!v.equals(other.v))
			return false;
		if (!Arrays.equals(verificationKeys, other.verificationKeys))
			return false;
		return true;
	}

}
