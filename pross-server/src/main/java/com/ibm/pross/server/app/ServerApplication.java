package com.ibm.pross.server.app;

import java.io.File;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

import org.apache.log4j.BasicConfigurator;
import org.apache.log4j.Level;
import org.apache.log4j.LogManager;
import org.apache.log4j.Logger;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import com.ibm.pross.server.app.avpss.ApvssShareholder;
import com.ibm.pross.server.app.http.HttpRequestProcessor;
import com.ibm.pross.server.communication.MessageDeliveryManager;
import com.ibm.pross.server.communication.handlers.ChainBuildingMessageHandler;
import com.ibm.pross.server.communication.pointtopoint.MessageReceiver;
import com.ibm.pross.server.configuration.permissions.AccessEnforcement;
import com.ibm.pross.server.configuration.permissions.ClientPermissionLoader;

import bftsmart.reconfiguration.util.sharedconfig.KeyLoader;
import bftsmart.reconfiguration.util.sharedconfig.ServerConfiguration;
import bftsmart.reconfiguration.util.sharedconfig.ServerConfigurationLoader;
import net.i2p.crypto.eddsa.EdDSASecurityProvider;

public class ServerApplication {

	static {
		Security.addProvider(new BouncyCastleProvider());
		Security.addProvider(new EdDSASecurityProvider());
	}

	public static String CONFIG_FILENAME = "common.config";
	public static String KEYS_DIRECTORY = "keys";
	public static String SAVE_DIRECTORY = "state";
	public static String AUTH_DIRECTORY = "../client/clients.config";

	private final ServerConfiguration configuration;
	private final KeyLoader keyLoader;
	private final ChainBuildingMessageHandler chainBuilder;

	public ServerApplication(final File baseDirectory, final int serverIndex)
			throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, InterruptedException {

		// Load configuration
		final File configFile = new File(baseDirectory, CONFIG_FILENAME);
		this.configuration = ServerConfigurationLoader.load(configFile);
		System.out.println(this.configuration);

		// Load keys
		final File keysDirectory = new File(baseDirectory, KEYS_DIRECTORY);
		this.keyLoader = new KeyLoader(keysDirectory, this.configuration.getNumServers(), serverIndex);
		System.out.println("Loaded encryption and verification keys");

		// Load Client Access Controls
		final AccessEnforcement accessEnforcement = ClientPermissionLoader
				.load(new File(baseDirectory, AUTH_DIRECTORY));

		// Setup persistent state for message broadcast and processing
		final List<InetSocketAddress> serverAddresses = this.configuration.getServerAddresses();
		final File saveDir = new File(baseDirectory, SAVE_DIRECTORY);
		final File serverSaveDir = new File(saveDir, "server-" + serverIndex);
		serverSaveDir.mkdirs();

		// Wait for messages and begin processing them as they arrive
		final int myPort = this.configuration.getServerAddresses().get(serverIndex - 1).getPort();
		final MessageReceiver messageReceiver = new MessageReceiver(myPort);
		messageReceiver.start();
		System.out.println("Listening on port: " + myPort);

		// Perform basic benchmark before starting up
		System.out.print("Benchmarking Algorithms: ");
		BenchmarkCli.runAllBenchmarks();

		// Create message handler for the Certified Chain
		final int optQuorum = (this.configuration.getNumServers() - this.configuration.getMaxLivenessFaults());
		this.chainBuilder = new ChainBuildingMessageHandler(serverIndex, optQuorum, this.keyLoader, serverSaveDir);

		// Create message manager to manage messages received over point to point links;
		final MessageDeliveryManager messageManager = new MessageDeliveryManager(serverAddresses, serverIndex,
				this.keyLoader, serverSaveDir, this.chainBuilder, messageReceiver);
		this.chainBuilder.setMessageManager(messageManager);

		// Create Shareholder for each secret to be maintained
		final ConcurrentMap<String, ApvssShareholder> shareholders = new ConcurrentHashMap<>();
		final int n = this.configuration.getNumServers();
		final int k = this.configuration.getReconstructionThreshold();
		final int f = this.configuration.getMaxSafetyFaults();
		for (final String secretName : accessEnforcement.getKnownSecrets()) {
			// Create Shareholder
			System.out.println("Starting APVSS Shareholder for secret: " + secretName);
			final ApvssShareholder shareholder = new ApvssShareholder(secretName, this.keyLoader, this.chainBuilder,
					serverIndex, n, k, f);
			shareholder.start(false); // Start the message processing thread but don't start the DKG
			shareholders.put(secretName, shareholder);
		}

		// Wait for BFT to setup
		while (!this.chainBuilder.isBftReady()) {
			Thread.sleep(100);
		}
		System.out.println("System ready.");

		// Start server to process client requests
		final HttpRequestProcessor requestProcessor = new HttpRequestProcessor(serverIndex, this.configuration,
				accessEnforcement, shareholders);
		requestProcessor.start();

		// Prompt user for action
//		final BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
//		System.out.println("Available Options:");
//		System.out.println("1. Initiate DKG");
//		System.out.println("2. Initiate Share Recovery");
//		System.out.println("3. Initiate Proactive Refresh");
//		System.out.println("4. Quit");
//		System.out.print("Enter selection: ");
//		while (true) {
//			final String input = reader.readLine();
//			switch (input) {
//			case "1":
//				System.out.println("Initiating DKG...");
//				doDistribuedKeyGeneration(shareholder);
//				break;
//			case "2":
//				System.out.println("Performing Share Recovery...");
//				break;
//			case "3":
//				System.out.println("Performing Proactive Refresh...");
//				break;
//			case "4":
//				System.out.println("Exiting...");
//				System.exit(0);
//				break;
//			default:
//				System.err.println("Unknown selection: " + input);
//			}
//		}
	}

	public static void main(final String[] args)
			throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, InterruptedException {

		// Configure logging
		BasicConfigurator.configure();
		final List<Logger> loggers = Collections.<Logger>list(LogManager.getCurrentLoggers());
		loggers.add(LogManager.getRootLogger());
		for (Logger logger : loggers) {
			logger.setLevel(Level.OFF);
		}

		// Delete BFT SMaRt's cache of the view
		final File configPath = new File("config");
		final File cachedView = new File(configPath, "currentView");
		cachedView.delete();

		// Print launch configuration
		System.out.println(Arrays.toString(args));

		// Parse arguments
		if (args.length < 2) {
			System.err.println("USAGE: config-dir server-index");
			System.exit(-1);
		}
		final File baseDirectory = new File(args[0]);
		final int serverIndex = Integer.parseInt(args[1]);

		// Start server
		new ServerApplication(baseDirectory, serverIndex);
	}

}
