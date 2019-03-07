package bftsmart.tom.util;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectInputStream;
import java.io.ObjectOutput;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;

import com.ibm.pross.common.util.SigningUtil;

public class InternalSignedObject implements Serializable {

	private static final long serialVersionUID = 6809472312206377981L;

	/*
	 * The original content is "deep copied" in its serialized format and stored in
	 * a byte array. The signature field is also in the form of byte array.
	 */
	private final byte[] content;
	private final byte[] signature;
	private final String algorithm;

	/**
	 * Constructs a SignedObject from any Serializable object. The given object is
	 * signed with the given signing key, using the designated signature engine.
	 *
	 * @param object        the object to be signed.
	 * @param signingKey    the private key for signing.
	 * @param signingEngine the signature signing engine.
	 *
	 * @exception IOException         if an error occurs during serialization
	 * @exception InvalidKeyException if the key is invalid.
	 * @exception SignatureException  if signing fails.
	 */
	public InternalSignedObject(Serializable object, PrivateKey signingKey)
			throws IOException, InvalidKeyException, SignatureException {

		// creating a stream pipe-line, from a to b
		ByteArrayOutputStream b = new ByteArrayOutputStream();
		ObjectOutput a = new ObjectOutputStream(b);

		// write and flush the object content to byte array
		a.writeObject(object);
		a.flush();
		a.close();
		this.content = b.toByteArray();
		b.close();

		// determine algorithm for the key type
		this.algorithm = SigningUtil.getSigningAlgorithm(signingKey);

		// now sign the encapsulated object
		this.signature = TOMUtil.signMessage(signingKey, content);
	}

	/**
	 * Retrieves the encapsulated object. The encapsulated object is de-serialized
	 * before it is returned.
	 *
	 * @return the encapsulated object.
	 *
	 * @exception IOException            if an error occurs during de-serialization
	 * @exception ClassNotFoundException if an error occurs during de-serialization
	 */
	public Object getObject() throws IOException, ClassNotFoundException {
		// creating a stream pipe-line, from b to a
		ByteArrayInputStream b = new ByteArrayInputStream(this.content);
		ObjectInput a = new ObjectInputStream(b);
		Object obj = a.readObject();
		b.close();
		a.close();
		return obj;
	}

	/**
	 * Retrieves the signature on the signed object, in the form of a byte array.
	 *
	 * @return the signature. Returns a new array each time this method is called.
	 */
	public byte[] getSignature() {
		return this.signature.clone();
	}

	/**
	 * Retrieves the name of the signature algorithm.
	 *
	 * @return the signature algorithm name.
	 */
	public String getAlgorithm() {
		return this.algorithm;
	}

	/**
	 * Verifies that the signature in this SignedObject is the valid signature for
	 * the object stored inside, with the given verification key, using the
	 * designated verification engine.
	 *
	 * @param verificationKey    the public key for verification.
	 *
	 * @exception SignatureException  if signature verification failed.
	 * @exception InvalidKeyException if the verification key is invalid.
	 *
	 * @return {@code true} if the signature is valid, {@code false} otherwise
	 */
	public boolean verify(PublicKey verificationKey)
			throws InvalidKeyException, SignatureException {
		return SigningUtil.verify(content, signature, verificationKey, algorithm);
	}

}
