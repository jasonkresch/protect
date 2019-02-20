package bftsmart.reconfiguration.util.sharedconfig;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;

public class ServerConfigurationLoader {
	
	public static final String NUM_SERVERS_KEY = "num_servers";
	public static final String MAX_BFT_FAULTS_KEY = "max_bft_faults";
	public static final String RECONSTRUCT_THRESHOLD_KEY = "reconstruction_threshold";
	public static final String MAX_SAFETY_FAULTS_KEY = "max_safety_faults";
	public static final String MAX_LIVENESS_FAULTS_KEY = "max_liveness_faults";
	public static final String NUM_SERVERS_KEY_PREFIX = "server.";
	
	public static ServerConfiguration load(final File configFile) throws IOException {

		final Properties properties = new Properties();

		final FileInputStream inputStream = new FileInputStream(configFile);

		// Load the properties file
		properties.load(inputStream);

		// Parse the parameters
		final int numServers = Integer.parseInt(properties.getProperty(NUM_SERVERS_KEY));
		final int maxBftFaults = Integer.parseInt(properties.getProperty(MAX_BFT_FAULTS_KEY));
		final int reconstructionThreshold = Integer.parseInt(properties.getProperty(RECONSTRUCT_THRESHOLD_KEY));
		final int maxSafetyFaults = Integer.parseInt(properties.getProperty(MAX_SAFETY_FAULTS_KEY));
		final int maxLivenessFaults = Integer.parseInt(properties.getProperty(MAX_LIVENESS_FAULTS_KEY));
		
		// Load each server's address
		final List<InetSocketAddress> serverAddresses = new ArrayList<>(numServers);
		for (int i = 1; i <= numServers; i++) {
			final String hostPort = properties.getProperty(NUM_SERVERS_KEY_PREFIX + i);
			final String[] parts = hostPort.split(":");
			final String host = parts[0];
			final int port = Integer.parseInt(parts[1]);
			final InetSocketAddress serverAddress = new InetSocketAddress(host, port);
			serverAddresses.add(serverAddress);
		}

		inputStream.close();

		return new ServerConfiguration(numServers, maxBftFaults, reconstructionThreshold, maxSafetyFaults, maxLivenessFaults, serverAddresses);
	}

}
