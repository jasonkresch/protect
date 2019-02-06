package com.ibm.pross.server.app;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.math.BigInteger;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;

import com.ibm.pross.common.util.crypto.paillier.PaillierKeyGenerator;
import com.ibm.pross.common.util.crypto.paillier.PaillierKeyPair;
import com.ibm.pross.common.util.crypto.paillier.PaillierPrivateKey;
import com.ibm.pross.common.util.crypto.paillier.PaillierPublicKey;

import net.i2p.crypto.eddsa.EdDSAPrivateKey;
import net.i2p.crypto.eddsa.EdDSAPublicKey;
import net.i2p.crypto.eddsa.EdDSASecurityProvider;

/**
 * Used to generate key pairs for servers
 */
public class KeyGeneratorCli {

	public static void main(String[] args) throws InvalidKeySpecException, NoSuchAlgorithmException, IOException {

		Security.addProvider(new BouncyCastleProvider());
		Security.addProvider(new EdDSASecurityProvider());
		
		// Check usage
		if (args.length < 2)
		{
			System.err.println("USAGE: key-path index");
		}
		final File keyPath = new File(args[0]);
		final int keyIndex = Integer.parseInt(args[1]);
		
		// Generate EC Key Pair
		//final KeyPair signingKeyPair = EcKeyGeneration.generateKeyPair();
		
		// Generate Ed25519 Key Pair
		final KeyPairGenerator keyGen = KeyPairGenerator.getInstance(EdDSASecurityProvider.PROVIDER_NAME);
		final KeyPair signingKeyPair = keyGen.generateKeyPair();
		
		// Generate Paillier Key Pair
		final PaillierKeyGenerator encryptionKeyGenerator = new PaillierKeyGenerator(2048);
		final PaillierKeyPair paillierKeyPair = encryptionKeyGenerator.generate();
		final KeyPair encryptionKeyPair = convertFromPaillier(paillierKeyPair);

		// Write public keys
		final File publicKeyFile = new File(keyPath, "public-" + keyIndex);
		try (PemWriter writer = new PemWriter(new FileWriter(publicKeyFile.getAbsolutePath()))) {
			writeObject(signingKeyPair.getPublic(), writer);
			writeObject(encryptionKeyPair.getPublic(), writer);
		}
		System.out.println("Wrote: " + publicKeyFile.getAbsolutePath());
		
		// Write private keys
		final File privateKeyFile = new File(keyPath, "private-" + keyIndex);
		try (PemWriter writer = new PemWriter(new FileWriter(privateKeyFile.getAbsolutePath()))) {
			writeObject(signingKeyPair.getPrivate(), writer);
			writeObject(encryptionKeyPair.getPrivate(), writer);
		}
		System.out.println("Wrote: " + privateKeyFile.getAbsolutePath());
	}

	private static void writeObject(final Key key, final PemWriter writer) throws IOException {

		final String description;
		if (key instanceof RSAPrivateKey) {
			description = "PAILLIER PRIVATE KEY";
		} else if (key instanceof RSAPublicKey) {
			description = "PAILLIER PUBLIC KEY";
		} else if (key instanceof ECPrivateKey) {
			description = "EC PRIVATE KEY";
		} else if (key instanceof ECPublicKey) {
			description = "EC PUBLIC KEY";
		} else if (key instanceof EdDSAPrivateKey) {
			description = "ED25519 PRIVATE KEY";
		} else if (key instanceof EdDSAPublicKey) {
			description = "ED25519 PUBLIC KEY";
		} else if (key instanceof PrivateKey) {
			description = "PRIVATE KEY";
		} else if (key instanceof PublicKey) {
			description = "PUBLIC KEY";
		} else {
			description = "KEY";
		}

		writer.writeObject(new PemObject(description, key.getEncoded()));
	}

	// Note this is only to take advantage of existing serialization methods
	public static KeyPair convertFromPaillier(final PaillierKeyPair paillierKeyPair)
			throws InvalidKeySpecException, NoSuchAlgorithmException {
		// Get keys
		final PaillierPrivateKey paillierPrivateKey = paillierKeyPair.getPrivateKey();
		final PaillierPublicKey paillierPublicKey = paillierKeyPair.getPublicKey();

		// Get fields
		final BigInteger n = paillierPublicKey.getN(); // treat as 'N'
		final BigInteger e = paillierPublicKey.getG(); // treat as 'e'
		final BigInteger d = paillierPrivateKey.getLambda(); // treat as 'd'

		// Represent them as RSA keys
		final RSAPrivateKeySpec privKeySpec = new RSAPrivateKeySpec(n, d);
		final RSAPublicKeySpec pubKeySpec = new RSAPublicKeySpec(n, e);

		// Convert to key pair
		final KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		final PublicKey rsaPublic = keyFactory.generatePublic(pubKeySpec);
		final PrivateKey rsaPrivate = keyFactory.generatePrivate(privKeySpec);

		return new KeyPair(rsaPublic, rsaPrivate);
	}

	// Note this is only to take advantage of existing serialization methods
	public static PaillierKeyPair convertToPaillier(final KeyPair rsaKeyPair)
			throws InvalidKeySpecException, NoSuchAlgorithmException {
		// Get keys
		final RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) rsaKeyPair.getPrivate();
		final RSAPublicKey rsaPublicKey = (RSAPublicKey) rsaKeyPair.getPublic();

		// Get fields
		final BigInteger n = rsaPublicKey.getModulus(); // treat as 'n'
		final BigInteger g = rsaPublicKey.getPublicExponent(); // treat as 'g'
		final BigInteger lambda = rsaPrivateKey.getPrivateExponent(); // treat as 'lambda'

		// Convert them back to Paillier keys
		final PaillierPrivateKey privKey = new PaillierPrivateKey(lambda, n);
		final PaillierPublicKey pubKey = new PaillierPublicKey(n, g);

		// Convert to key pair
		return new PaillierKeyPair(pubKey, privKey);
	}
	
	// Note this is only to take advantage of existing serialization methods
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
