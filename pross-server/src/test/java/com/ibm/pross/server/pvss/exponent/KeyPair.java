package com.ibm.pross.server.pvss.exponent;

import java.math.BigInteger;

import com.ibm.pross.common.util.RandomNumberGenerator;
import com.ibm.pross.common.util.crypto.ecc.EcCurve;
import com.ibm.pross.common.util.crypto.ecc.EcPoint;

public class KeyPair {

	private final EcPoint G;
	private final EcPoint H;
	private final EcCurve curve;
	
	private final PrivateKey privateKey;
	private final PublicKey publicKey;
	
	private KeyPair(final EcPoint G, final EcPoint H, final EcCurve curve, final BigInteger x)
	{
		this.G = G;
		this.H = H;
		this.curve = curve;
		
		// Store private key
		this.privateKey = new PrivateKey(x);
		
		// Store public key
		final EcPoint Gx = this.curve.multiply(G, x);
		final EcPoint Hx = this.curve.multiply(H, x);
		this.publicKey = new PublicKey(Gx, Hx);
	}
	
	public static KeyPair generateKeyPair(final EcPoint g, final EcPoint h, final EcCurve curve)
	{
		final BigInteger x = RandomNumberGenerator.generateRandomInteger(curve.getR());
		return new KeyPair(g, h, curve, x);
	}

	public EcPoint getG() {
		return G;
	}

	public EcPoint getH() {
		return H;
	}

	public EcCurve getCurve() {
		return curve;
	}

	public PrivateKey getPrivateKey() {
		return privateKey;
	}

	public PublicKey getPublicKey() {
		return publicKey;
	}
	
}
