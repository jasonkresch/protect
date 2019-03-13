package com.ibm.pross.server.app;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.security.KeyPair;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.AbstractMap.SimpleEntry;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.io.pem.PemReader;

import com.ibm.pross.common.config.ServerConfiguration;
import com.ibm.pross.common.config.ServerConfigurationLoader;
import com.ibm.pross.common.util.certificates.CertificateGeneration;
import com.ibm.pross.common.util.crypto.ecc.EcKeyGeneration;
import com.ibm.pross.common.util.serialization.Pem;
import com.ibm.pross.server.configuration.permissions.AccessEnforcement;
import com.ibm.pross.server.configuration.permissions.ClientPermissionLoader;

import net.i2p.crypto.eddsa.EdDSASecurityProvider;


public class CertificateAuthorityCli {

	public static final String ISSUER_DN = "O=Threshold, OU=Security, CN=PROTECT CA";

	public static void main(final String args[]) throws IOException, CertificateException, NoSuchAlgorithmException,
			InvalidKeySpecException, KeyStoreException {

		Security.addProvider(new BouncyCastleProvider());
		Security.addProvider(new EdDSASecurityProvider());

		// Check usage
		if (args.length < 4) {
			System.err.println("USAGE: ca-path key-path cert-path [servers=true/false]");
			System.exit(1);
		}

		// Get directories from arguments
		final File caPath = new File(args[0]);
		final File keyPath = new File(args[1]);
		final File certPath = new File(args[2]);
		final boolean areServers = Boolean.parseBoolean(args[3]);

		if (areServers) {
			// Generate Server Certificates using server configuration
			// These IP addresses will have subject alternative names
			issueServerCertificates(caPath, keyPath, certPath);
		} else {
			// Generate Client Certificates using client configuration
			// These certificates will all be issued by the same client CA
			issueClientCertificates(caPath, keyPath, certPath);
		}

	}

	protected static SimpleEntry<X509Certificate, PrivateKey> loadOrGenerateCa(final File caPath, final String caName)
			throws IOException, CertificateException, NoSuchAlgorithmException, InvalidKeySpecException {

		// File names for CA cert and key
		final File caCertificateFile = new File(caPath, "ca-cert-" + caName + ".pem");
		final File caPrivateKeyFile = new File(caPath, "ca-key-" + caName);

		// Attempt to load from file
		try {
			final X509Certificate caCert = Pem.loadCertificateFromFile(caCertificateFile);
			final PrivateKey caPrivateKey = (PrivateKey) Pem.loadKeyFromFile(caPrivateKeyFile);
			System.out.println("Loaded CA certificate from file: " + caCertificateFile.getAbsolutePath());
			System.out.println("Loaded CA private key from file: " + caPrivateKeyFile.getAbsolutePath());
			return new SimpleEntry<>(caCert, caPrivateKey);
		} catch (final FileNotFoundException e) {

			// Generate new ECDSA Key Pair
			final KeyPair caKeyPair = EcKeyGeneration.generateKeyPair();
			final PrivateKey caPrivateKey = (PrivateKey) caKeyPair.getPrivate();

			// Create self-signed root CA certificate
			final X509Certificate caCert = CertificateGeneration.generateCaCertificate(ISSUER_DN + " " + caName, caKeyPair);

			// Write CA certificate to file
			Pem.storeCertificateToFile(caCert, caCertificateFile);
			System.out.println("Wrote: " + caCertificateFile.getAbsolutePath());

			// Write CA private key to file
			Pem.storeKeyToFile(caPrivateKey, caPrivateKeyFile);
			System.out.println("Wrote: " + caPrivateKeyFile.getAbsolutePath());

			return new SimpleEntry<>(caCert, caPrivateKey);
		}
	}


	private static final void issueServerCertificates(final File caPath, final File keyPath, final File certPath)
			throws IOException, CertificateException, NoSuchAlgorithmException, InvalidKeySpecException {

		// Load configuration to get server addresses
		final File baseDirectory = new File(caPath.getParent());
		final File serverDirectory = new File(baseDirectory, "server");
		final File configFile = new File(serverDirectory, ServerApplication.CONFIG_FILENAME);
		final ServerConfiguration configuration = ServerConfigurationLoader.load(configFile);

		// For each ECDSA public key in the keyPath, create a certificate
		for (int keyIndex = 1; keyIndex <= configuration.getNumServers(); keyIndex++) {

			final File publicKeyFile = new File(keyPath, "public-" + keyIndex);

			if (!publicKeyFile.exists()) {
				System.out.println(publicKeyFile.getAbsoluteFile() + " not found, skipping...");
				continue;
			} else {
				// Load CA certificate (or generate a new one)
				final SimpleEntry<X509Certificate, PrivateKey> entry = loadOrGenerateCa(caPath, "server-" + keyIndex);
				System.out.println();

				final String issuerDn = entry.getKey().getIssuerDN().getName();
				final PrivateKey caKey = entry.getValue();

				try (final PemReader reader = new PemReader(new FileReader(publicKeyFile.getAbsolutePath()))) {
					// Load public key from file
					final PublicKey publicKey = ((PublicKey) Pem.readObject(reader.readPemObject()));
					System.out.println("Read: " + publicKeyFile.getAbsolutePath());

					// Generate certificate
					final String subjectDn = "O=Threshold, OU=Security, CN=server-" + keyIndex;

					System.out.println("  Issued certificate for: " + subjectDn);

					final InetSocketAddress serverAddress = configuration.getServerAddresses().get(keyIndex - 1);
					final String serverIp = serverAddress.getAddress().toString().split("/")[1];
					final String serverHost = serverAddress.getAddress().getCanonicalHostName();
					final X509Certificate certificate = CertificateGeneration.generateCertificate(subjectDn, serverIp, serverHost, publicKey,
							730, false, issuerDn, caKey);
					System.out.println("  Alternative names: IP:" + serverIp + ", DNS:" + serverHost);

					// Write certificate file
					final File certificateFile = new File(certPath, "cert-" + keyIndex);
					Pem.storeCertificateToFile(certificate, certificateFile);
					System.out.println("Wrote: " + certificateFile.getAbsolutePath());
					System.out.println();

				}
			}
		}
	}

	private static final void issueClientCertificates(final File caPath, final File keyPath, final File certPath)
			throws NoSuchAlgorithmException, CertificateException, KeyStoreException, IOException,
			InvalidKeySpecException {

		// Load configuration to get server addresses
		final File baseDirectory = new File(caPath.getParent());
		final File serverDirectory = new File(baseDirectory, "server");
		final File configFile = new File(serverDirectory, ServerApplication.AUTH_DIRECTORY);

		// Load Client Access Controls
		final AccessEnforcement accessEnforcement = ClientPermissionLoader.loadIniFile(configFile);

		// Load or generate client CA Certificate
		final SimpleEntry<X509Certificate, PrivateKey> clientCaEntry = loadOrGenerateCa(caPath, "clients");
		final String issuerDnClient = clientCaEntry.getKey().getIssuerDN().getName();
		final PrivateKey caKeyClient = clientCaEntry.getValue();
		System.out.println();

		// For each ECDSA public key in the keyPath, create a certificate
		for (final String username : accessEnforcement.getKnownUsers()) {

			final File publicKeyFile = new File(keyPath, "public-" + username);

			if (!publicKeyFile.exists()) {
				System.out.println(publicKeyFile.getAbsoluteFile() + " not found, skipping...");
				continue;
			} else {

				try (final PemReader reader = new PemReader(new FileReader(publicKeyFile.getAbsolutePath()))) {

					// Load client public key from file
					final PublicKey publicKey = ((PublicKey) Pem.readObject(reader.readPemObject()));
					System.out.println("Read: " + publicKeyFile.getAbsolutePath());

					// Generate certificate
					final String subjectDn = "O=Threshold, OU=Security, CN=client-" + username;

					final X509Certificate certificate = CertificateGeneration.generateCertificate(subjectDn, null, null, publicKey, 730,
							false, issuerDnClient, caKeyClient);

					System.out.println("  Issued certificate for: " + subjectDn);

					// Load entity private key from file
					final File privateKeyFile = new File(keyPath, "private-" + username);
					try (final PemReader keyReader = new PemReader(new FileReader(privateKeyFile.getAbsolutePath()))) {
						final PrivateKey privateKey = ((PrivateKey) Pem.readObject(keyReader.readPemObject()));

						// Write PKCS12 file for import to browsers
						final File pfxFile = new File(keyPath, "bundle-private-" + username + ".p12");
						CertificateGeneration.createP12File(pfxFile, "password".toCharArray(), certificate, privateKey);
						System.out.println("Wrote: " + pfxFile.getAbsolutePath());
					}

					// Write certificate file
					final File certificateFile = new File(certPath, "cert-" + username);
					Pem.storeCertificateToFile(certificate, certificateFile);
					System.out.println("Wrote: " + certificateFile.getAbsolutePath());
					System.out.println();
				}
			}
		}
	}


}
