package com.ibm.pross.server.app;

import java.io.File;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
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

import com.ibm.pross.common.config.KeyLoader;
import com.ibm.pross.common.config.ServerConfiguration;
import com.ibm.pross.common.config.ServerConfigurationLoader;
import com.ibm.pross.common.util.serialization.Pem;
import com.ibm.pross.server.app.avpss.ApvssShareholder;
import com.ibm.pross.server.app.http.HttpRequestProcessor;
import com.ibm.pross.server.communication.MessageDeliveryManager;
import com.ibm.pross.server.communication.handlers.ChainBuildingMessageHandler;
import com.ibm.pross.server.communication.pointtopoint.MessageReceiver;
import com.ibm.pross.server.configuration.permissions.AccessEnforcement;
import com.ibm.pross.server.configuration.permissions.ClientPermissionLoader;

import net.i2p.crypto.eddsa.EdDSASecurityProvider;

public class ServerApplication {

	static {
		Security.addProvider(new BouncyCastleProvider());
		Security.addProvider(new EdDSASecurityProvider());
	}

	public static String CONFIG_FILENAME = "common.config";
	public static String SERVER_KEYS_DIRECTORY = "keys";
	public static String CERTS_DIRECTORY = "certs";
	public static String SAVE_DIRECTORY = "state";
	public static String CLIENT_KEYS_DIRECTORY = "../client/keys";
	public static String AUTH_DIRECTORY = "../client/clients.config";
	public static String CA_DIRECTORY = "../ca";

	public ServerApplication(final File baseDirectory, final int serverIndex)
			throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, InterruptedException,
			CertificateException, KeyManagementException, UnrecoverableKeyException, KeyStoreException {

		// Load configuration
		final File configFile = new File(baseDirectory, CONFIG_FILENAME);
		final ServerConfiguration configuration = ServerConfigurationLoader.load(configFile);
		System.out.println(configuration);

		// Load server keys
		final File keysDirectory = new File(baseDirectory, SERVER_KEYS_DIRECTORY);
		final KeyLoader serverKeys = new KeyLoader(keysDirectory, configuration.getNumServers(), serverIndex);
		System.out.println("Loaded encryption and verification keys");

		// Load Client Access Controls
		final AccessEnforcement accessEnforcement = ClientPermissionLoader.loadIniFile(new File(baseDirectory, AUTH_DIRECTORY));

		// Setup persistent state for message broadcast and processing
		final List<InetSocketAddress> serverAddresses = configuration.getServerAddresses();
		final File saveDir = new File(baseDirectory, SAVE_DIRECTORY);
		final File serverSaveDir = new File(saveDir, "server-" + serverIndex);
		serverSaveDir.mkdirs();

		// Wait for messages and begin processing them as they arrive
		final int myPort = configuration.getServerAddresses().get(serverIndex - 1).getPort();
		final MessageReceiver messageReceiver = new MessageReceiver(myPort);
		messageReceiver.start();
		System.out.println("Listening on port: " + myPort);

		// Perform basic benchmark before starting up
		System.out.print("Benchmarking Algorithms: ");
		BenchmarkCli.runAllBenchmarks();

		// Create message handler for the Certified Chain
		final int optQuorum = (configuration.getNumServers() - configuration.getMaxLivenessFaults());
		final ChainBuildingMessageHandler chainBuilder = new ChainBuildingMessageHandler(serverIndex, optQuorum,
				serverKeys, serverSaveDir);

		// Create message manager to manage messages received over point to point links;
		final MessageDeliveryManager messageManager = new MessageDeliveryManager(serverAddresses, serverIndex,
				serverKeys, serverSaveDir, chainBuilder, messageReceiver);
		chainBuilder.setMessageManager(messageManager);

		// Create Shareholder for each secret to be maintained
		final ConcurrentMap<String, ApvssShareholder> shareholders = new ConcurrentHashMap<>();
		final int n = configuration.getNumServers();
		final int k = configuration.getReconstructionThreshold();
		for (final String secretName : accessEnforcement.getKnownSecrets()) {
			// Create Shareholder
			System.out.println("Starting APVSS Shareholder for secret: " + secretName);
			final ApvssShareholder shareholder = new ApvssShareholder(secretName, serverKeys, chainBuilder, serverIndex,
					n, k);
			shareholder.start(false); // Start the message processing thread but don't start the DKG
			shareholders.put(secretName, shareholder);
		}

		// Wait for BFT to setup
		while (!chainBuilder.isBftReady()) {
			Thread.sleep(100);
		}
		System.out.println("BFT ready.");

		// Load certificates to support TLS
		final File caDirectory = new File(baseDirectory, CA_DIRECTORY);
		final File certDirectory = new File(baseDirectory, CERTS_DIRECTORY);
		final File hostCertificateFile = new File(certDirectory, "cert-" + serverIndex);
		final List<X509Certificate> caCerts = new ArrayList<>();
		for (int i = 1; i <= configuration.getNumServers(); i++) {
			final File caCertificateFile = new File(caDirectory, "ca-cert-server-" + i + ".pem");
			caCerts.add(Pem.loadCertificateFromFile(caCertificateFile));
		}
		final File caCertificateFile = new File(caDirectory, "ca-cert-clients.pem");
		caCerts.add(Pem.loadCertificateFromFile(caCertificateFile));
		final X509Certificate hostCert = Pem.loadCertificateFromFile(hostCertificateFile);

		// Load client authentication keys
		final File clientKeysDirectory = new File(baseDirectory, CLIENT_KEYS_DIRECTORY);
		final KeyLoader clientKeys = new KeyLoader(clientKeysDirectory, accessEnforcement.getKnownUsers());
		System.out.println("Loaded client keys");

		// Start server to process client requests
		final HttpRequestProcessor requestProcessor = new HttpRequestProcessor(serverIndex, configuration,
				accessEnforcement, shareholders, caCerts, hostCert, serverKeys.getTlsKey(), clientKeys, serverKeys);
		requestProcessor.start();

	}

	public static void main(final String[] args)
			throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, InterruptedException,
			CertificateException, KeyManagementException, UnrecoverableKeyException, KeyStoreException {
		
		// Configure logging
		BasicConfigurator.configure();
		@SuppressWarnings("unchecked")
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
