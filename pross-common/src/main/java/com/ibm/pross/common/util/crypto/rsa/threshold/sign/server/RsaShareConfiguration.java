package com.ibm.pross.common.util.crypto.rsa.threshold.sign.server;

import com.ibm.pross.common.util.shamir.ShamirShare;

/**
 * Represents complete state of the server for a particular user registration
 */
public class RsaShareConfiguration {

	private final ServerPublicConfiguration publicConfiguration;

	// Private information unique to this server
	private final ShamirShare share;

	public RsaShareConfiguration(final ServerPublicConfiguration publicConfiguration, final ShamirShare share) {
		this.publicConfiguration = publicConfiguration;
		this.share = share;
	}

	public ServerPublicConfiguration getServerPublicConfiguration() {
		return publicConfiguration;
	}

	public ShamirShare getShare() {
		return this.share;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((publicConfiguration == null) ? 0 : publicConfiguration.hashCode());
		result = prime * result + ((share == null) ? 0 : share.hashCode());
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
		RsaShareConfiguration other = (RsaShareConfiguration) obj;
		if (publicConfiguration == null) {
			if (other.publicConfiguration != null)
				return false;
		} else if (!publicConfiguration.equals(other.publicConfiguration))
			return false;
		if (share == null) {
			if (other.share != null)
				return false;
		} else if (!share.equals(other.share))
			return false;
		return true;
	}

}
