package com.ibm.pross.server.app;

import java.io.File;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.List;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import com.ibm.pross.server.app.avpss.ApvssShareholder;
import com.ibm.pross.server.communication.MessageDeliveryManager;
import com.ibm.pross.server.communication.handlers.ChainBuildingMessageHandler;
import com.ibm.pross.server.communication.pointtopoint.MessageReceiver;
import com.ibm.pross.server.configuration.Configuration;
import com.ibm.pross.server.configuration.ConfigurationLoader;
import com.ibm.pross.server.configuration.KeyLoader;

public class ServerApplication {

	static {
		Security.addProvider(new BouncyCastleProvider());
	}

	public static String CONFIG_FILENAME = "common.config";
	public static String KEYS_DIRECTORY = "keys";
	public static String SAVE_DIRECTORY = "state";

	
	private final Configuration configuration;
	private final KeyLoader keyLoader;
	private final ChainBuildingMessageHandler chainBuilder;
	
	public ServerApplication(final File baseDirectory, final int serverIndex) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, InterruptedException
	{
		// Load configuration
		final File configFile = new File(baseDirectory, CONFIG_FILENAME);
		this.configuration = ConfigurationLoader.load(configFile);
		System.out.println(this.configuration);

		// Load keys
		final File keysDirectory = new File(baseDirectory, KEYS_DIRECTORY);
		this.keyLoader = new KeyLoader(keysDirectory, this.configuration.getNumServers(), serverIndex);
		System.out.println("Loaded encryption and verification keys");

		// Setup persistent state for message broadcast and processing
		final List<InetSocketAddress> serverAddresses = this.configuration.getServerAddresses();
		final File saveDir = new File(baseDirectory, SAVE_DIRECTORY);
		final File saveFile = new File(saveDir, "message-state-" + serverIndex + ".dat");

		// Wait for messages and begin processing them as they arrive
		final int myPort = this.configuration.getServerAddresses().get(serverIndex - 1).getPort();
		final MessageReceiver messageReceiver = new MessageReceiver(myPort);
		messageReceiver.start();
		System.out.println("Listening on port: " + myPort);

		// Create message handler for the Certified Chain
		final int optQuorum = (this.configuration.getNumServers() - this.configuration.getMaxLivenessFaults());
		this.chainBuilder = new ChainBuildingMessageHandler(serverIndex, optQuorum, this.keyLoader);
		
		// Create message manager to manage messages received over point to point links;
		final MessageDeliveryManager messageManager = new MessageDeliveryManager(serverAddresses, serverIndex, this.keyLoader,
				saveFile, this.chainBuilder, messageReceiver);
		this.chainBuilder.setMessageManager(messageManager);
		
		
		Thread.sleep(10_000);
		
		
		// Create DKG shareholder
		
		// Define parameters
		final int n = configuration.getNumServers();
		final int k = configuration.getMaxSafetyFaults() + 1;
		final int f = configuration.getMaxLivenessFaults();

		final long start = System.nanoTime();
		System.err.println("Starting shareholder: t=" + start);
		
		// Create shareholder
		
		final ApvssShareholder shareholder = new ApvssShareholder(keyLoader, this.chainBuilder, serverIndex, n, k, f, true);
		//if (serverIndex != 3)
		shareholder.start(true);
		shareholder.waitForQual();

		System.err.println("Share established!");
		
		// Wait for completion
		shareholder.waitForPublicKeys();
		
		final long end = System.nanoTime();
		System.err.println("Completed shareholder: time took =" + (((double)(end - start)) / 1_000_000.0));
		
		shareholder.stop();

		System.err.println("Created share: " + shareholder.getShare1().getY());
		System.err.println("Share public key: " + shareholder.getSecretPublicKey());
		System.err.println("Done!");
	}
	
	public static void main(final String[] args)
			throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, InterruptedException {
		System.out.println(Arrays.toString(args));

		// Parse arguments
		if (args.length < 2) {
			System.err.println("USAGE: config-dir server-index");
			System.exit(-1);
		}
		final File baseDirectory = new File(args[0]);
		final int serverIndex = Integer.parseInt(args[1]);
		
		final ServerApplication serverApplication = new ServerApplication(baseDirectory, serverIndex);

	}

}
