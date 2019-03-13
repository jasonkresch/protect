package com.ibm.pross.common.util.certificates;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;

import com.ibm.pross.common.util.RandomNumberGenerator;
import com.ibm.pross.common.util.SigningUtil;

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
public class CertificateGeneration {


	/**
	 * Generates a self-signed root CA certificate from a given distinguished name
	 * and key pair
	 * 
	 * @param caDistinguishedName
	 * @param caKeyPair
	 * @return
	 */
	public static X509Certificate generateCaCertificate(final String caDistinguishedName, final KeyPair caKeyPair) {

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
	public static X509Certificate generateCertificate(final String subjectDn, final String altNameIp,
			final String altNameHost, final PublicKey subjectPublicKey, final long validForDays, final boolean makeCa,
			final String issuerDn, final PrivateKey caPrivateKey) {

		try {

			// Look up algorithm based on CA private key
			final String algorithm = SigningUtil.getSigningAlgorithm(caPrivateKey);
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
				generalNames.add(new GeneralName(new DNSName(altNameHost)));
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
	

	/**
	 * Create a bundled file with the client certificate and private key.
	 * 
	 * Warning there is no strong password protecting this file, it should be
	 * treated equivalently to the client private key
	 * 
	 * @param p12File
	 * @param password
	 * @param clientCert
	 * @param privateKey
	 * @throws NoSuchAlgorithmException
	 * @throws CertificateException
	 * @throws IOException
	 * @throws KeyStoreException
	 */
	public static void createP12File(final File p12File, final char[] password, final X509Certificate clientCert,
			final PrivateKey privateKey)
			throws NoSuchAlgorithmException, CertificateException, IOException, KeyStoreException {

		// Create PKCS12 (PFX) file
		final KeyStore keyStore = KeyStore.getInstance("PKCS12");

		keyStore.load(null, password);

		// Add certificate and private key for the server
		keyStore.setKeyEntry("host", privateKey, password, new X509Certificate[] { clientCert });

		// Store file
		try (FileOutputStream keyStoreOutputStream = new FileOutputStream(p12File)) {
			keyStore.store(keyStoreOutputStream, password);
		}
	}
}
