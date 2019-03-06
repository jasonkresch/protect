package com.ibm.pross.server.app;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.AbstractMap.SimpleEntry;
import java.util.Date;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.io.pem.PemReader;

import com.ibm.pross.common.CommonConfiguration;
import com.ibm.pross.common.util.RandomNumberGenerator;
import com.ibm.pross.common.util.crypto.ecc.EcKeyGeneration;
import com.ibm.pross.common.util.serialization.Pem;

import bftsmart.reconfiguration.util.sharedconfig.ServerConfiguration;
import bftsmart.reconfiguration.util.sharedconfig.ServerConfigurationLoader;
import net.i2p.crypto.eddsa.EdDSASecurityProvider;
import sun.security.x509.AlgorithmId;
import sun.security.x509.BasicConstraintsExtension;
import sun.security.x509.CertificateAlgorithmId;
import sun.security.x509.CertificateExtensions;
import sun.security.x509.CertificateSerialNumber;
import sun.security.x509.CertificateValidity;
import sun.security.x509.CertificateVersion;
import sun.security.x509.CertificateX509Key;
import sun.security.x509.DNSName;
import sun.security.x509.GeneralName;
import sun.security.x509.GeneralNames;
import sun.security.x509.IPAddressName;
import sun.security.x509.SubjectAlternativeNameExtension;
import sun.security.x509.X500Name;
import sun.security.x509.X509CertImpl;
import sun.security.x509.X509CertInfo;

@SuppressWarnings("restriction")
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

		// Load configuration to get server addresses
		final File baseDirectory = new File(caPath.getParent());
		final File serverDirectory = new File(baseDirectory, "server");
		final File configFile = new File(serverDirectory, ServerApplication.CONFIG_FILENAME);
		final ServerConfiguration configuration = ServerConfigurationLoader.load(configFile);

		// For each ECDSA public key in the keyPath, create a certificate
		for (int keyIndex = 1; keyIndex <= configuration.getNumServers(); keyIndex++) {

			final File publicKeyFile = new File(keyPath, "public-" + keyIndex);

			if (!publicKeyFile.exists()) {
				break;
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
					final String subjectDn;
					if (areServers) {
						subjectDn = "O=Threshold, OU=Security, CN=server-" + keyIndex;
					} else {
						subjectDn = "O=Threshold, OU=Security, CN=client-" + keyIndex;
					}

					System.out.println("  Issued certificate for: " + subjectDn);

					final X509Certificate certificate;
					if (areServers) {
						final InetSocketAddress serverAddress = configuration.getServerAddresses().get(keyIndex - 1);
						final String serverIp = serverAddress.getAddress().toString().split("/")[1];
						final String serverHost = serverAddress.getAddress().getCanonicalHostName();
						certificate = generateCertificate(subjectDn, serverIp, serverHost, publicKey, 730, false,
								issuerDn, caKey);
						System.out.println("  Alternative names: IP:" + serverIp + ", DNS:" + serverHost);
					} else {
						final SimpleEntry<X509Certificate, PrivateKey> clientCaEntry = loadOrGenerateCa(caPath,
								"clients");
						final String issuerDnClient = clientCaEntry.getKey().getIssuerDN().getName();
						final PrivateKey caKeyClient = clientCaEntry.getValue();
						certificate = generateCertificate(subjectDn, null, null, publicKey, 730, false, issuerDnClient,
								caKeyClient);

						// Load entity private key from file
						final File privateKeyFile = new File(keyPath, "private-" + keyIndex);
						try (final PemReader keyReader = new PemReader(
								new FileReader(privateKeyFile.getAbsolutePath()))) {
							final PrivateKey privateKey = ((PrivateKey) Pem.readObject(keyReader.readPemObject()));

							// Write PKCS12 file for import to browsers
							final File pfxFile = new File(keyPath, "private-bundle-" + keyIndex + ".pfx");
							createPfxFile(pfxFile, "password".toCharArray(), certificate, privateKey);
							System.out.println("Wrote: " + pfxFile.getAbsolutePath());
						}
					}

					// Write certificate file
					final File certificateFile = new File(certPath, "cert-" + keyIndex);
					Pem.storeCertificateToFile(certificate, certificateFile);
					System.out.println("Wrote: " + certificateFile.getAbsolutePath());
					System.out.println();

				}
			}
		}

	}

	protected static SimpleEntry<X509Certificate, PrivateKey> loadOrGenerateCa(final File caPath, final String keyIndex)
			throws IOException, CertificateException, NoSuchAlgorithmException, InvalidKeySpecException {

		// File names for CA cert and key
		final File caCertificateFile = new File(caPath, "ca-cert-" + keyIndex + ".pem");
		final File caPrivateKeyFile = new File(caPath, "ca-key-" + keyIndex);

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
			final X509Certificate caCert = generateCaCertificate(ISSUER_DN + " " + keyIndex, caKeyPair);

			// Write CA certificate to file
			Pem.storeCertificateToFile(caCert, caCertificateFile);
			System.out.println("Wrote: " + caCertificateFile.getAbsolutePath());

			// Write CA private key to file
			Pem.storeKeyToFile(caPrivateKey, caPrivateKeyFile);
			System.out.println("Wrote: " + caPrivateKeyFile.getAbsolutePath());

			return new SimpleEntry<>(caCert, caPrivateKey);
		}
	}

	public static void createPfxFile(final File pfxFile, final char[] password, final X509Certificate clientCert,
			final PrivateKey privateKey)
			throws NoSuchAlgorithmException, CertificateException, IOException, KeyStoreException {

		// Create PKCS12 (PFX) file
		final KeyStore keyStore = KeyStore.getInstance("PKCS12");

		keyStore.load(null, password);

		// Add certificate and private key for the server
		keyStore.setKeyEntry("host", privateKey, password, new X509Certificate[] { clientCert });

		// Store file
		try (FileOutputStream keyStoreOutputStream = new FileOutputStream(pfxFile)) {
			keyStore.store(keyStoreOutputStream, password);
		}
	}

	/**
	 * Generates a self-signed root CA certificate from a given distinguished name
	 * and key pair
	 * 
	 * @param caDistinguishedName
	 * @param caKeyPair
	 * @return
	 */
	protected static X509Certificate generateCaCertificate(final String caDistinguishedName, final KeyPair caKeyPair) {

		// Validity period of 10 years
		final int validityDays = 20 * 365;

		// Add basic constraints to allow this certificate to issue other certificates
		final boolean makeCa = true;

		// to generate a self signed certificate pass the CA key pair in as
		// both the ca key and the signee key
		final X509Certificate caCertificate = generateCertificate(caDistinguishedName, null, null,
				caKeyPair.getPublic(), validityDays, makeCa, caDistinguishedName, caKeyPair.getPrivate());

		return caCertificate;
	}

	/**
	 * Issues an X.509v3 certificate signed by the given Certificate Authority
	 * 
	 * @param subjectDn
	 * @param altNameIp        Subject alternative name IP address (may be null)
	 * @param altNameHost      Subject alternative name hostname (may be null)
	 * @param subjectPublicKey
	 * @param validForDays
	 * @param makeCa
	 * @param issuerDn
	 * @param caPrivateKey
	 * @return
	 */
	protected static X509Certificate generateCertificate(final String subjectDn, final String altNameIp,
			final String altNameHost, final PublicKey subjectPublicKey, final long validForDays, final boolean makeCa,
			final String issuerDn, final PrivateKey caPrivateKey) {

		try {

			// Look up algorithm based on CA private key
			final String algorithm = CommonConfiguration.EC_SIGNATURE_ALGORITHM;
			final AlgorithmId algorithmId = AlgorithmId.get(algorithm);

			// Define validity period
			final Date notBefore = new Date(new Date().getTime() - 300); // 5 minutes prior to avoid clock skew issues
			final Date notAfter = new Date(notBefore.getTime() + (validForDays * 24 * 3600 * 1000));
			final CertificateValidity validity = new CertificateValidity(notBefore, notAfter);

			// Random serial number
			final BigInteger serialNumber = RandomNumberGenerator.generateRandomInteger(128);

			// Define information within certificate
			final X509CertInfo certificateInfo = new X509CertInfo();
			certificateInfo.set(X509CertInfo.VERSION, new CertificateVersion(CertificateVersion.V3));
			certificateInfo.set(X509CertInfo.VALIDITY, validity);
			certificateInfo.set(X509CertInfo.SERIAL_NUMBER, new CertificateSerialNumber(serialNumber));
			certificateInfo.set(X509CertInfo.SUBJECT, new X500Name(subjectDn));
			certificateInfo.set(X509CertInfo.ISSUER, new X500Name(issuerDn));
			certificateInfo.set(X509CertInfo.KEY, new CertificateX509Key(subjectPublicKey));
			certificateInfo.set(X509CertInfo.ALGORITHM_ID, new CertificateAlgorithmId(algorithmId));
			// certificateInfo.set(CertificateAlgorithmId.NAME + "." +
			// CertificateAlgorithmId.ALGORITHM, algorithmId);

			// Process extensions
			final CertificateExtensions extensions = new CertificateExtensions();
			// Make the issued certificate a sub-CA of this one (or self-signed)
			final BasicConstraintsExtension bce = new BasicConstraintsExtension(makeCa, 0);
			extensions.set(BasicConstraintsExtension.NAME,
					new BasicConstraintsExtension(true, bce.getExtensionValue()));

			// Add a subject alternative name (if not null)
			if (altNameIp != null) {
				final GeneralNames generalNames = new GeneralNames();
				generalNames.add(new GeneralName(new IPAddressName(altNameIp)));
				//generalNames.add(new GeneralName(new DNSName(altNameHost)));
				final SubjectAlternativeNameExtension san = new SubjectAlternativeNameExtension(false, generalNames);
				extensions.set(SubjectAlternativeNameExtension.NAME, san);
			}

			certificateInfo.set(X509CertInfo.EXTENSIONS, extensions);

			// Create and sign the certificate
			final X509CertImpl certificate = new X509CertImpl(certificateInfo);
			certificate.sign(caPrivateKey, algorithm);

			return certificate;

		} catch (GeneralSecurityException | IOException e) {
			throw new RuntimeException(e);
		}
	}

}
