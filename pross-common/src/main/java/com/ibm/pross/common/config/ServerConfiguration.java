package com.ibm.pross.common.config;

import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Represents the configuration state of the system of servers
 */
public class ServerConfiguration {

	private final int numServers; // N
	private final int maxBftFaults; // F
	private final int reconstructionThreshold; // K
	private final int maxSafetyFaults; // t_S
	private final int maxLivenessFaults; // t_L
	private final List<InetSocketAddress> serverAddresses;

	public ServerConfiguration(final int numServers, final int maxBftFaults, final int reconstructionThreshold,
			final int maxSafetyFaults, final int maxLivenessFaults, List<InetSocketAddress> serverAddresses) {
		this.numServers = numServers;
		this.maxBftFaults = maxBftFaults;
		this.reconstructionThreshold = reconstructionThreshold;
		this.maxSafetyFaults = maxSafetyFaults;
		this.maxLivenessFaults = maxLivenessFaults;
		this.serverAddresses = new ArrayList<InetSocketAddress>(serverAddresses);

		verifyConstraints();
	}

	private void verifyConstraints() {
		boolean validConfig = true;

		// Validate constraints on numServers
		if (!(this.numServers > 0)) {
			System.err.println("num_servers must be greater than zero");
			validConfig = false;
		}

		// Validate constraints on reconstructionThreshold
		if (!(this.reconstructionThreshold <= this.numServers)) {
			System.err.println("reconstruction_threshold must be less than or equal to num_servers");
			validConfig = false;
		}
		if (!(this.reconstructionThreshold > this.maxSafetyFaults)) {
			System.err.println("reconstruction_threshold must be greater than max_safety_faults");
			validConfig = false;
		}

		// Validate constraints on maxSafetyFaults
		if (!(this.maxSafetyFaults >= 0)) {
			System.err.println("max_safety_faults must be greater than or equal to zero");
			validConfig = false;
		}
		if (!(this.maxSafetyFaults < this.reconstructionThreshold)) {
			System.err.println("max_safety_faults must be less than reconstruction_threshold");
			validConfig = false;
		}
		if (!(this.maxSafetyFaults <= (this.numServers - (2 * this.maxLivenessFaults) - 1))) {
			System.err.println(
					"max_safety_faults must be less than or equal to (num_servers - (2 * max_liveness_faults) - 1");
			validConfig = false;
		}

		// Validate constraints on maxLivenessFaults
		if (!(this.maxLivenessFaults >= 0)) {
			System.err.println("max_liveness_faults must be greater than or equal to zero");
			validConfig = false;
		}
		if (!(this.maxLivenessFaults <= this.maxSafetyFaults)) {
			System.err.println("max_liveness_faults must be less than or equal to max_safety_faults");
			validConfig = false;
		}
		if (!(this.maxLivenessFaults <= ((this.numServers - maxSafetyFaults - 1) / 2))) {
			System.err.println(
					"max_safety_faults must be less than or equal to ((num_servers - max_safety_faults - 1) / 2)");
			validConfig = false;
		}

		// Validate constraints on maxBftFaults
		if (!(this.maxBftFaults >= 0)) {
			System.err.println("max_bft_faults must be greater than or equal to zero");
			validConfig = false;
		}
		if (!(this.maxBftFaults <= ((this.numServers - 1) / 3))) {
			System.err.println("max_bft_faults must be less than or equal to ((num_servers - 1) / 3)");
			validConfig = false;
		}
		
		if (this.serverAddresses.size() != this.numServers)
		{
			System.err.println("The number of defined server addresses must equal num_servers");
			validConfig = false;
		}

		if (validConfig == false) {
			throw new IllegalArgumentException("Server Configuration is not valid");
		}
	}

	public List<InetSocketAddress> getServerAddresses() {
		return Collections.unmodifiableList(serverAddresses);
	}

	public int getNumServers() {
		return numServers;
	}

	public int getMaxBftFaults() {
		return maxBftFaults;
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
		result = prime * result + maxBftFaults;
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
		ServerConfiguration other = (ServerConfiguration) obj;
		if (maxBftFaults != other.maxBftFaults)
			return false;
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
		return "ServerConfiguration [numServers=" + numServers + ", maxBftFaults=" + maxBftFaults
				+ ", reconstructionThreshold=" + reconstructionThreshold + ", maxSafetyFaults=" + maxSafetyFaults
				+ ", maxLivenessFaults=" + maxLivenessFaults + ", serverAddresses=" + serverAddresses + "]";
	}

}
