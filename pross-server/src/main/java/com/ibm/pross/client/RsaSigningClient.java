package com.ibm.pross.client;

import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Date;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.DigestInfo;

import com.ibm.pross.common.util.Exponentiation;
import com.ibm.pross.common.util.RandomNumberGenerator;

import sun.security.util.DerOutputStream;
import sun.security.util.DerValue;
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
public class RsaSigningClient {

	public static final String HASH_ALGORITHM = "SHA-512";
	public static final String CERTIFICATE_SIGNING_ALGORITHM = "SHA512withRSA"; // Must match hash algorithm

	protected static X509CertInfo createCertificateInfo(final String subjectDn, final String altNameIp,
			final String altNameHost, final PublicKey subjectPublicKey, final long validForDays, final boolean makeCa,
			final String issuerDn) {

		try {

			// Look up algorithm based on CA private key
			final AlgorithmId algorithmId = AlgorithmId.get(CERTIFICATE_SIGNING_ALGORITHM);

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

			return certificateInfo;

		} catch (GeneralSecurityException | IOException e) {
			throw new RuntimeException(e);
		}
	}

	static final X509Certificate createCertificateFromTbsAndSignature(X509CertInfo info, final byte[] signature)
			throws CertificateException, NoSuchAlgorithmException, InvalidKeyException, NoSuchProviderException,
			SignatureException {

		try (DerOutputStream out = new DerOutputStream(); DerOutputStream tmp = new DerOutputStream();) {

			// Append the certificate information
			info.encode(tmp);

			// Append the signature algorithm
			final AlgorithmId algId = AlgorithmId.get(CERTIFICATE_SIGNING_ALGORITHM);
			algId.encode(tmp);

			// Append the signature
			tmp.putBitString(signature);

			// Wrap the signed data in a SEQUENCE { data, algorithm, sig }
			out.write(DerValue.tag_Sequence, tmp);
			byte[] signedCert = out.toByteArray();

			// Create a certificate
			return new X509CertImpl(signedCert);

		} catch (IOException e) {
			throw new CertificateEncodingException(e.toString());
		}
	}

	public static BigInteger EMSA_PKCS1_V1_5_ENCODE(byte[] input, final BigInteger modulus)
			throws NoSuchAlgorithmException, IOException {

		// Digest the input
		final MessageDigest md = MessageDigest.getInstance(HASH_ALGORITHM);
		final byte[] digest = md.digest(input);

		// Create a digest info consisting of the algorithm id and the hash
		final AlgorithmIdentifier algId = new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha512, DERNull.INSTANCE);
		final DigestInfo digestInfo = new DigestInfo(algId, digest);
		final byte[] message = digestInfo.getEncoded(ASN1Encoding.DER);

		// Do PKCS1 padding
		final byte[] block = new byte[(modulus.bitLength() / 8) - 1];
		System.arraycopy(message, 0, block, block.length - message.length, message.length);
		block[0] = 0x01; // type code 1
		for (int i = 1; i != block.length - message.length - 1; i++) {
			block[i] = (byte) 0xFF;
		}

		return new BigInteger(1, block);
	}

	public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException,
			IOException, CertificateException, NoSuchProviderException {

		// Key generation
		KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
		generator.initialize(1024);
		KeyPair rsaKeyPair = generator.generateKeyPair();
		RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) rsaKeyPair.getPrivate();
		RSAPublicKey rsaPublicKey = (RSAPublicKey) rsaKeyPair.getPublic();

		// Generate certificate without a signature
		final X509CertInfo certInfo = createCertificateInfo("CN=test", null, null, rsaKeyPair.getPublic(), 365, true,
				"CN=test");
		final X509CertImpl certificate = new X509CertImpl(certInfo);
		final byte[] toBeSigned = certificate.getTBSCertificate();

		// Manually sign it
		final BigInteger toBeSignedRaw = EMSA_PKCS1_V1_5_ENCODE(toBeSigned, rsaPublicKey.getModulus());
		final byte[] signature = Exponentiation
				.modPow(toBeSignedRaw, rsaPrivateKey.getPrivateExponent(), rsaPrivateKey.getModulus()).toByteArray();

		// Create the certificate passing in the signature
		final X509Certificate cert = createCertificateFromTbsAndSignature(certInfo, signature);

		System.out.println(cert);
		cert.verify(rsaKeyPair.getPublic());
		System.out.println("Certificate is valid!");
	}

}
