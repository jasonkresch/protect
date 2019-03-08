package com.ibm.pross.common.util.crypto.rsa.threshold.sign.server;

import java.math.BigInteger;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import com.ibm.pross.common.util.crypto.rsa.threshold.sign.data.SignatureResponse;
import com.ibm.pross.common.util.crypto.rsa.threshold.sign.exceptions.BadArgumentException;
import com.ibm.pross.common.util.crypto.rsa.threshold.sign.exceptions.UserNotFoundException;
import com.ibm.pross.common.util.crypto.rsa.threshold.sign.math.ThresholdSignatures;
import com.ibm.pross.common.util.shamir.ShamirShare;

/**
 * A server maintains public and private information with each registered user
 * (Initialized via a dealer). The dealer establishes secret information which
 * can only be recovered through the interaction with a threshold number of
 * well-behaved servers.
 * 
 * The servers, however, learn nothing of this secret and only a threshold
 * number of compromised servers may collude to defeat the confidentiality of
 * the secret.
 */
public class RsaSignatureServer {

	private final int THROTTLE_MILLISECONDS = 10;

	// Map of usernames to their corresponding configurations
	private final Map<String, RsaShareConfiguration> userConfigurations;

	// Map of usernames to their corresponding throttle mechanisms
	private final Map<String, Throttle> throttling = new ConcurrentHashMap<>();

	public RsaSignatureServer() {
		this.userConfigurations = new ConcurrentHashMap<>();
	}

	/**
	 * Registers public and private configuration data under this username. Returns
	 * true if this username was not known.
	 * 
	 * @param username
	 * @param configuration
	 * @param shamirShare
	 * @return
	 * @throws BadArgumentException
	 */
	public boolean register(String username, ServerPublicConfiguration publicConfig, ShamirShare share)
			throws BadArgumentException {

		checkConfigurationConsistency(publicConfig, share);

		RsaShareConfiguration serverConfig = new RsaShareConfiguration(publicConfig, share);
		return this.userConfigurations.putIfAbsent(username, serverConfig) == null;
	}

	/**
	 * Common method used to load server configuration
	 * 
	 * @param username
	 * @return ServerConfiguration registered for the user
	 * @throws UserNotFoundException If there is no registered server configuration
	 *                               for this user
	 */
	private RsaShareConfiguration getConfigurationForUser(String username) throws UserNotFoundException {
		RsaShareConfiguration serverConfig = this.userConfigurations.get(username);
		if (serverConfig == null) {
			throw new UserNotFoundException("User nor found: " + username);
		}
		return serverConfig;
	}

	/**
	 * Returns the unique "index" of this server for the provided username, where
	 * the index is defined as the x-coordinate for the share held by this server
	 * 
	 * @param username
	 * @return
	 * @throws UserNotFoundException
	 */
	public int getIndex(String username) throws UserNotFoundException {
		RsaShareConfiguration serverConfig = getConfigurationForUser(username);
		return serverConfig.getShare().getX().intValue();
	}

	/**
	 * Returns the set of configuration that is common and public to all servers for
	 * this user
	 * 
	 * @param username
	 * @return
	 * @throws Exception
	 */
	public ServerPublicConfiguration getPublicConfiguration(String username) throws UserNotFoundException {
		RsaShareConfiguration serverConfig = getConfigurationForUser(username);
		return serverConfig.getServerPublicConfiguration();
	}

	/**
	 * Generates a signature share along with a proof of correctness for the given
	 * message to be signed. A threshold of such signature shares can be combined to
	 * yield the signature.
	 * 
	 * @param message
	 * @return
	 * @throws UserNotFoundException
	 * @throws BadArgumentException
	 */
	public SignatureResponse computeSignatureShare(final String username, final BigInteger message)
			throws UserNotFoundException, BadArgumentException {

		// Perform throttling to prevent brute-force attacks
		throttling.putIfAbsent(username, new Throttle(THROTTLE_MILLISECONDS));
		throttling.get(username).performThrottledAction();

		// Load user configuration
		RsaShareConfiguration serverConfig = getConfigurationForUser(username);

		return ThresholdSignatures.produceSignatureResponse(message, serverConfig);
	}

	// Create key shares

	/**
	 * Generate empty set of servers
	 * 
	 * @param serverCount
	 * @return
	 */
	public static RsaSignatureServer[] initializeServers(final int serverCount) {
		final RsaSignatureServer[] servers = new RsaSignatureServer[serverCount];
		for (int i = 0; i < servers.length; i++) {
			servers[i] = new RsaSignatureServer();
		}
		return servers;
	}

	/**
	 * Executes some sanity checks on the server configuration
	 * 
	 * @param publicConf
	 * @param privateConf
	 * @throws BadArgumentException
	 */
	public static void checkConfigurationConsistency(final ServerPublicConfiguration publicConf, ShamirShare share)
			throws BadArgumentException {

		final int serverCount = publicConf.getServerCount();

		if (publicConf.getE().longValue() <= serverCount) {
			throw new BadArgumentException("e must be greater than the number of servers!");
		}

		if (share.getX().compareTo(BigInteger.valueOf(serverCount)) > 0) {
			throw new BadArgumentException("Share index cannot exceed number of servers");
		}

	}
}
