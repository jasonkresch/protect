package bftsmart.reconfiguration.util.sharedconfig;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.util.io.pem.PemReader;

import com.ibm.pross.common.util.serialization.Pem;

/**
 * <pre>
 * Used to load public and private keys from: 
 *   config/server/keys/public-<id+1>
 *   config/server/keys/private-<id+1>
 * </pre>
 */
public class KeyLoader {

	private final List<PublicKey> tlsPublicKeys;
	private final List<PublicKey> verificationKeys;
	private final List<PublicKey> encryptionKeys;

	private final PrivateKey tlsKey;
	private final PrivateKey signingKey;
	private final PrivateKey decryptionKey;

	// Keys to user ids
	private final Map<String, Integer> serverTlsKeyMap = new ConcurrentHashMap<>();

	// Keys to user names
	private final Map<String, String> userTlsKeyMap = new ConcurrentHashMap<>();

	public KeyLoader(final File keyPath, final int numServers, final int myIndex) throws FileNotFoundException,
			IOException, NoSuchAlgorithmException, InvalidKeySpecException, CertificateException {

		this.tlsPublicKeys = new ArrayList<>(numServers);
		this.verificationKeys = new ArrayList<>(numServers);
		this.encryptionKeys = new ArrayList<>(numServers);

		// Load all public keys
		for (int keyIndex = 1; keyIndex <= numServers; keyIndex++) {
			final File publicKeyFile = new File(keyPath, "public-" + keyIndex);

			try (final PemReader reader = new PemReader(new FileReader(publicKeyFile.getAbsolutePath()))) {
				final PublicKey tlsPublicKey = (PublicKey) Pem.readObject(reader.readPemObject());
				this.tlsPublicKeys.add(tlsPublicKey);
				this.serverTlsKeyMap.put(Hex.encodeHexString(tlsPublicKey.getEncoded()), keyIndex);

				this.verificationKeys.add((PublicKey) Pem.readObject(reader.readPemObject()));
				this.encryptionKeys.add((PublicKey) Pem.readObject(reader.readPemObject()));
			}
		}

		// Load private key for our index
		final File publicKeyFile = new File(keyPath, "private-" + myIndex);
		try (final PemReader reader = new PemReader(new FileReader(publicKeyFile.getAbsolutePath()))) {
			this.tlsKey = (PrivateKey) Pem.readObject(reader.readPemObject());
			this.signingKey = (PrivateKey) Pem.readObject(reader.readPemObject());
			this.decryptionKey = (PrivateKey) Pem.readObject(reader.readPemObject());
		}
	}

	public KeyLoader(final File keyPath, final Set<String> keyNames) throws FileNotFoundException, IOException,
			NoSuchAlgorithmException, InvalidKeySpecException, CertificateException {

		this.tlsPublicKeys = new ArrayList<>(keyNames.size());
		this.verificationKeys = new ArrayList<>(keyNames.size());
		this.encryptionKeys = new ArrayList<>(keyNames.size());

		// Load all public keys
		for (String username : keyNames) {
			final File publicKeyFile = new File(keyPath, "public-" + username);

			try (final PemReader reader = new PemReader(new FileReader(publicKeyFile.getAbsolutePath()))) {
				final PublicKey tlsPublicKey = (PublicKey) Pem.readObject(reader.readPemObject());
				this.tlsPublicKeys.add(tlsPublicKey);
				this.userTlsKeyMap.put(Hex.encodeHexString(tlsPublicKey.getEncoded()), username);

				this.verificationKeys.add((PublicKey) Pem.readObject(reader.readPemObject()));
				this.encryptionKeys.add((PublicKey) Pem.readObject(reader.readPemObject()));
			}
		}
		
		this.tlsKey = null;
		this.signingKey = null;
		this.decryptionKey = null;
	}

	public PublicKey getEncryptionKey(int entityIndex) {
		return this.encryptionKeys.get(entityIndex - 1);
	}

	public PublicKey getVerificationKey(int entityIndex) {
		return this.verificationKeys.get(entityIndex - 1);
	}

	public PublicKey getTlsPublicKey(int entityIndex) {
		return this.tlsPublicKeys.get(entityIndex - 1);
	}

	public PrivateKey getTlsKey() {
		return this.tlsKey;
	}

	public PrivateKey getSigningKey() {
		return this.signingKey;
	}

	public PrivateKey getDecryptionKey() {
		return this.decryptionKey;
	}

	public Integer getEntityIndex(final PublicKey peerPublicKey) {
		return this.serverTlsKeyMap.get(Hex.encodeHexString(peerPublicKey.getEncoded()));
	}

	public String getUsername(final PublicKey peerPublicKey) {
		return this.userTlsKeyMap.get(Hex.encodeHexString(peerPublicKey.getEncoded()));
	}

	@Override
	public String toString() {
		return "KeyLoader [tlsPublicKeys=" + tlsPublicKeys + ", verificationKeys=" + verificationKeys
				+ ", encryptionKeys=" + encryptionKeys + ", tlsKey=" + tlsKey + ", signingKey=" + signingKey
				+ ", decryptionKey=" + decryptionKey + "]";
	}

}
