package com.ibm.pross.server.configuration;

import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Represents the configuration state of the system of servers
 */
public class Configuration {

	private final int numServers;
	private final int reconstructionThreshold;
	private final int maxSafetyFaults;
	private final int maxLivenessFaults;
	private final List<InetSocketAddress> serverAddresses;

	public Configuration(final int numServers, final int reconstructionThreshold, final int maxSafetyFaults,
			final int maxLivenessFaults, List<InetSocketAddress> serverAddresses) {
		this.numServers = numServers;
		this.reconstructionThreshold = reconstructionThreshold;
		this.maxSafetyFaults = maxSafetyFaults;
		this.maxLivenessFaults = maxLivenessFaults;
		this.serverAddresses = new ArrayList<InetSocketAddress>(serverAddresses);
	}

	public List<InetSocketAddress> getServerAddresses() {
		return Collections.unmodifiableList(serverAddresses);
	}

	public int getNumServers() {
		return numServers;
	}

	public int getReconstructionThreshold() {
		return reconstructionThreshold;
	}

	public int getMaxSafetyFaults() {
		return maxSafetyFaults;
	}

	public int getMaxLivenessFaults() {
		return maxLivenessFaults;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + maxLivenessFaults;
		result = prime * result + maxSafetyFaults;
		result = prime * result + numServers;
		result = prime * result + reconstructionThreshold;
		result = prime * result + ((serverAddresses == null) ? 0 : serverAddresses.hashCode());
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
		Configuration other = (Configuration) obj;
		if (maxLivenessFaults != other.maxLivenessFaults)
			return false;
		if (maxSafetyFaults != other.maxSafetyFaults)
			return false;
		if (numServers != other.numServers)
			return false;
		if (reconstructionThreshold != other.reconstructionThreshold)
			return false;
		if (serverAddresses == null) {
			if (other.serverAddresses != null)
				return false;
		} else if (!serverAddresses.equals(other.serverAddresses))
			return false;
		return true;
	}

	@Override
	public String toString() {
		return "Configuration [numServers=" + numServers + ", reconstructionThreshold=" + reconstructionThreshold
				+ ", maxSafetyFaults=" + maxSafetyFaults + ", maxLivenessFaults=" + maxLivenessFaults
				+ ", serverAddresses=" + serverAddresses + "]";
	}

}
