package bftsmart.reconfiguration.util.sharedconfig;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.math.BigInteger;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;

import com.ibm.pross.common.util.crypto.paillier.PaillierPrivateKey;
import com.ibm.pross.common.util.crypto.paillier.PaillierPublicKey;

/**
 * <pre>
 * Used to load public and private keys from: 
 *   config/server/keys/public-<id+1>
 *   config/server/keys/private-<id+1>
 * </pre>
 */
public class KeyLoader {

	private final List<PublicKey> verificationKeys;
	private final List<PublicKey> encryptionKeys;

	private final PrivateKey signingKey;
	private final PrivateKey decryptionKey;

	public KeyLoader(final File keyPath, final int numServers, final int myIndex)
			throws FileNotFoundException, IOException, NoSuchAlgorithmException, InvalidKeySpecException {
		
		this.verificationKeys = new ArrayList<>(numServers);
		this.encryptionKeys = new ArrayList<>(numServers);

		// Load all public keys
		for (int keyIndex = 1; keyIndex <= numServers; keyIndex++) {
			final File publicKeyFile = new File(keyPath, "public-" + keyIndex);

			try (PemReader reader = new PemReader(new FileReader(publicKeyFile.getAbsolutePath()))) {
				this.verificationKeys.add((PublicKey) deserializeKey(reader.readPemObject()));
				this.encryptionKeys.add((PublicKey) deserializeKey(reader.readPemObject()));
			}
		}

		// Load private key for our index
		final File publicKeyFile = new File(keyPath, "private-" + myIndex);
		try (PemReader reader = new PemReader(new FileReader(publicKeyFile.getAbsolutePath()))) {
			this.signingKey = (PrivateKey) deserializeKey(reader.readPemObject());
			this.decryptionKey = (PrivateKey) deserializeKey(reader.readPemObject());
		}
	}

	private static Key deserializeKey(final PemObject pemObject)
			throws NoSuchAlgorithmException, InvalidKeySpecException {

		final KeyFactory edKeyFactory = KeyFactory.getInstance("EdDSA");
		final KeyFactory ecKeyFactory = KeyFactory.getInstance("ECDSA");
		final KeyFactory rsaKeyFactory = KeyFactory.getInstance("RSA");

		switch (pemObject.getType()) {
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

	public PublicKey getEncryptionKey(int serverIndex) {
		return this.encryptionKeys.get(serverIndex - 1);
	}

	public PublicKey getVerificationKey(int serverIndex) {
		return this.verificationKeys.get(serverIndex - 1);
	}
	
	public PrivateKey getSigningKey() {
		return this.signingKey;
	}

	public PrivateKey getDecryptionKey() {
		return this.decryptionKey;
	}

	@Override
	public String toString() {
		return "KeyLoader [verificationKeys=" + verificationKeys + ", encryptionKeys=" + encryptionKeys
				+ ", signingKey=" + signingKey + ", decryptionKey=" + decryptionKey + "]";
	}

}
