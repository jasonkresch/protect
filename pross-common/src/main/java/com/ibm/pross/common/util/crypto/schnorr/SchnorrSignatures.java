package com.ibm.pross.common.util.crypto.schnorr;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;

import org.apache.commons.codec.Charsets;
import org.bouncycastle.util.Arrays;

import com.ibm.pross.common.config.CommonConfiguration;
import com.ibm.pross.common.util.RandomNumberGenerator;
import com.ibm.pross.common.util.crypto.ecc.EcCurve;
import com.ibm.pross.common.util.crypto.ecc.EcPoint;
import com.ibm.pross.common.util.serialization.Parse;

public class SchnorrSignatures {
	
	public static byte[] sign(final EcCurve curve, final MessageDigest md, final BigInteger privateKey, byte[] message)
	{
		// Generate nonce
		final BigInteger fieldModulus = curve.getR();
		final BigInteger k = RandomNumberGenerator.generateRandomPositiveInteger(fieldModulus);
		
		// Calculate r = g^k
		final EcPoint r = curve.multiply(curve.getG(), k);
		byte[] serializedR = Parse.concatenate(r);
		
		// Compute e as hash(R, M)
		byte[] challenge = Parse.concatenate(serializedR, message);
		BigInteger e = new BigInteger(1, md.digest(challenge));
		
		// Compute s = k - xe
		BigInteger s = (k.subtract(privateKey.multiply(e))).mod(fieldModulus);
		
		return Parse.concatenate(s, e);
	}

	public static void verifySchnorrSignature(final EcCurve curve, final MessageDigest md, EcPoint publicKey, byte[] message, byte[] signature) throws SignatureException
	{
		byte[][] sePair = Parse.splitArrays(signature);
		final BigInteger s = new BigInteger(1, sePair[0]);
		final BigInteger e = new BigInteger(1, sePair[1]);
		
		final EcPoint gS = curve.multiply(curve.getG(), s);
		final EcPoint yE = curve.multiply(publicKey, e);
		final EcPoint rv = curve.addPoints(gS, yE);
		
		byte[] serializedRV = Parse.concatenate(rv);
		byte[] challenge = Parse.concatenate(serializedRV, message);
		final BigInteger ev = new BigInteger(1, md.digest(challenge));
		
		if (Arrays.constantTimeAreEqual(e.toByteArray(), ev.toByteArray()))
		{
			// Valid signature
		} else {
			// Bad Signature!
			throw new SignatureException("Signature does not match!");
		}
	}

	public static void main(String[] args) throws NoSuchAlgorithmException, SignatureException
	{
		// Static fields
		final  EcCurve curve = CommonConfiguration.CURVE;
		final EcPoint generator = curve.getG();
		final BigInteger fieldModulus = curve.getR();

		final MessageDigest md = MessageDigest.getInstance("SHA-256");
		
		final BigInteger privateSigningKey = RandomNumberGenerator.generateRandomPositiveInteger(fieldModulus);
		final EcPoint publicVerificationKey = curve.multiply(generator, privateSigningKey);
		
		byte[] message = "Hello World!".getBytes(Charsets.UTF_8);
		byte[] signature = sign(curve, md, privateSigningKey, message);
		
		verifySchnorrSignature(curve, md, publicVerificationKey, message, signature);
		
		System.out.println("Verified signature!");
		
		verifySchnorrSignature(curve, md, publicVerificationKey, "Wrong message".getBytes(), signature);
	}
	
}
