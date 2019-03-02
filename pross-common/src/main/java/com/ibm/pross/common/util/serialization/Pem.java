package com.ibm.pross.common.util.serialization;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.math.BigInteger;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.bouncycastle.util.io.pem.PemWriter;

import com.ibm.pross.common.util.crypto.paillier.PaillierPrivateKey;
import com.ibm.pross.common.util.crypto.paillier.PaillierPublicKey;

import net.i2p.crypto.eddsa.EdDSAPrivateKey;
import net.i2p.crypto.eddsa.EdDSAPublicKey;

public class Pem {

	public static void writeObject(final Object object, final PemWriter writer)
			throws IOException, CertificateEncodingException {

		final String description;
		if (object instanceof Certificate) {
			description = "CERTIFICATE";
		} else if (object instanceof RSAPrivateKey) {
			description = "PAILLIER PRIVATE KEY";
		} else if (object instanceof RSAPublicKey) {
			description = "PAILLIER PUBLIC KEY";
		} else if (object instanceof ECPrivateKey) {
			description = "EC PRIVATE KEY";
		} else if (object instanceof ECPublicKey) {
			description = "EC PUBLIC KEY";
		} else if (object instanceof EdDSAPrivateKey) {
			description = "ED25519 PRIVATE KEY";
		} else if (object instanceof EdDSAPublicKey) {
			description = "ED25519 PUBLIC KEY";
		} else if (object instanceof PrivateKey) {
			description = "PRIVATE KEY";
		} else if (object instanceof PublicKey) {
			description = "PUBLIC KEY";
		} else if (object instanceof Key) {
			description = "KEY";
		} else {
			throw new IllegalArgumentException("Unknwon object type");
		}

		final byte[] encoded = (object instanceof Key) ? ((Key) object).getEncoded()
				: ((Certificate) object).getEncoded();

		writer.writeObject(new PemObject(description, encoded));
	}

	public static Object readObject(final PemObject pemObject)
			throws NoSuchAlgorithmException, InvalidKeySpecException, CertificateException {

		final CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
		final KeyFactory edKeyFactory = KeyFactory.getInstance("EdDSA");
		final KeyFactory ecKeyFactory = KeyFactory.getInstance("ECDSA");
		final KeyFactory rsaKeyFactory = KeyFactory.getInstance("RSA");

		switch (pemObject.getType()) {
		case "CERTIFICATE":
			return certFactory.generateCertificate(new ByteArrayInputStream(pemObject.getContent()));
		case "PAILLIER PRIVATE KEY":
			final RSAPrivateKey privateKey = (RSAPrivateKey) rsaKeyFactory
					.generatePrivate(new PKCS8EncodedKeySpec(pemObject.getContent()));
			return convertToPaillierPrivateKey(privateKey);
		case "PAILLIER PUBLIC KEY":
			final RSAPublicKey publicKey = (RSAPublicKey) rsaKeyFactory
					.generatePublic(new X509EncodedKeySpec(pemObject.getContent()));
			return convertToPaillierPublicKey(publicKey);
		case "EC PRIVATE KEY":
			return ecKeyFactory.generatePrivate(new PKCS8EncodedKeySpec(pemObject.getContent()));
		case "EC PUBLIC KEY":
			return ecKeyFactory.generatePublic(new X509EncodedKeySpec(pemObject.getContent()));
		case "ED25519 PRIVATE KEY":
			return edKeyFactory.generatePrivate(new PKCS8EncodedKeySpec(pemObject.getContent()));
		case "ED25519 PUBLIC KEY":
			return edKeyFactory.generatePublic(new X509EncodedKeySpec(pemObject.getContent()));
		case "PRIVATE KEY":
			return edKeyFactory.generatePrivate(new PKCS8EncodedKeySpec(pemObject.getContent()));
		case "PUBLIC KEY":
			return edKeyFactory.generatePublic(new X509EncodedKeySpec(pemObject.getContent()));
		default:
			throw new IllegalArgumentException("Unrecognized type");
		}
	}

	public static void storeCertificateToFile(final X509Certificate certificate, final File certificateFile)
			throws CertificateEncodingException, IOException {
		try (PemWriter writer = new PemWriter(new FileWriter(certificateFile.getAbsolutePath()))) {
			Pem.writeObject(certificate, writer);
		}
	}

	public static X509Certificate loadCertificateFromFile(final File certificateFile)
			throws CertificateException, NoSuchAlgorithmException, InvalidKeySpecException, IOException {
		try (final PemReader reader = new PemReader(new FileReader(certificateFile.getAbsolutePath()))) {
			return (X509Certificate) Pem.readObject(reader.readPemObject());
		}
	}

	public static void storeKeyToFile(final Key key, final File keyFile)
			throws CertificateException, NoSuchAlgorithmException, InvalidKeySpecException, IOException {
		try (PemWriter writer = new PemWriter(new FileWriter(keyFile.getAbsolutePath()))) {
			Pem.writeObject(key, writer);
		}
	}

	public static Key loadKeyFromFile(final File keyFile)
			throws CertificateException, NoSuchAlgorithmException, InvalidKeySpecException, IOException {
		try (final PemReader reader = new PemReader(new FileReader(keyFile.getAbsolutePath()))) {
			return (Key) Pem.readObject(reader.readPemObject());
		}
	}

	public static PaillierPrivateKey convertToPaillierPrivateKey(final RSAPrivateKey rsaPrivateKey)
			throws InvalidKeySpecException, NoSuchAlgorithmException {

		// Get fields
		final BigInteger n = rsaPrivateKey.getModulus(); // treat as 'n'
		final BigInteger lambda = rsaPrivateKey.getPrivateExponent(); // treat as 'lambda'

		// Convert them back to Paillier private key
		return new PaillierPrivateKey(lambda, n);
	}

	// Note this is only to take advantage of existing serialization methods
	public static PaillierPublicKey convertToPaillierPublicKey(final RSAPublicKey rsaPublicKey)
			throws InvalidKeySpecException, NoSuchAlgorithmException {

		// Get fields
		final BigInteger n = rsaPublicKey.getModulus(); // treat as 'n'
		final BigInteger g = rsaPublicKey.getPublicExponent(); // treat as 'g'

		// Convert them back to Paillier public key
		return new PaillierPublicKey(n, g);
	}

}
