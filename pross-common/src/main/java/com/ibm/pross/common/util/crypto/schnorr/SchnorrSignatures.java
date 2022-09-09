package com.ibm.pross.common.util.crypto.schnorr;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.util.SortedMap;
import java.util.TreeMap;

import org.apache.commons.codec.Charsets;
import org.bouncycastle.util.Arrays;

import com.ibm.pross.common.config.CommonConfiguration;
import com.ibm.pross.common.util.RandomNumberGenerator;
import com.ibm.pross.common.util.crypto.ecc.EcCurve;
import com.ibm.pross.common.util.crypto.ecc.EcPoint;
import com.ibm.pross.common.util.serialization.Parse;
import com.ibm.pross.common.util.shamir.Polynomials;
import com.ibm.pross.common.util.shamir.Shamir;
import com.ibm.pross.common.util.shamir.ShamirShare;

public class SchnorrSignatures {
	
	public static byte[] sign1(final EcCurve curve, final MessageDigest md, final BigInteger privateKey, final EcPoint publicKey, byte[] message)
	{
		// Generate nonce
		final BigInteger fieldModulus = curve.getR();
		final BigInteger k = RandomNumberGenerator.generateRandomPositiveInteger(fieldModulus);
		
		// Calculate r = g^k
		final EcPoint r = curve.multiply(curve.getG(), k);
		
		// Compute e as hash(R, Y, m)
		byte[] challenge = Parse.concatenate(Parse.concatenate(r), Parse.concatenate(publicKey), message);
		BigInteger e = new BigInteger(1, md.digest(challenge));
		
		// Compute s = k - xe
		BigInteger s = (k.subtract(privateKey.multiply(e))).mod(fieldModulus);
		
		return Parse.concatenate(s, e);
	}

	public static void verifySchnorrSignature1(final EcCurve curve, final MessageDigest md, final EcPoint publicKey, byte[] message, byte[] signature) throws SignatureException
	{
		byte[][] sePair = Parse.splitArrays(signature);
		final BigInteger s = new BigInteger(1, sePair[0]);
		final BigInteger e = new BigInteger(1, sePair[1]);
		
		final EcPoint gS = curve.multiply(curve.getG(), s);
		final EcPoint yE = curve.multiply(publicKey, e);
		final EcPoint rv = curve.addPoints(gS, yE);
		
		byte[] challenge = Parse.concatenate(Parse.concatenate(rv), Parse.concatenate(publicKey), message);
		final BigInteger ev = new BigInteger(1, md.digest(challenge));
		
		if (Arrays.constantTimeAreEqual(e.toByteArray(), ev.toByteArray()))
		{
			// Valid signature
		} else {
			// Bad Signature!
			throw new SignatureException("Signature does not match!");
		}
	}

	
	
	public static byte[] sign2(final EcCurve curve, final MessageDigest md, final BigInteger privateKey, final EcPoint publicKey, byte[] message)
	{
		// Generate nonce
		final BigInteger fieldModulus = curve.getR();
		final BigInteger k = RandomNumberGenerator.generateRandomPositiveInteger(fieldModulus);
		
		// Calculate r = g^k
		final EcPoint r = curve.multiply(curve.getG(), k);
		
		// Compute e as hash(R, Y, m)
		byte[] challenge = Parse.concatenate(Parse.concatenate(r), Parse.concatenate(publicKey), message);
		BigInteger c = new BigInteger(1, md.digest(challenge));
		
		// Compute z = k -+ sc
		BigInteger z = (k.add(privateKey.multiply(c))).mod(fieldModulus);
		
		return Parse.concatenate(Parse.concatenate(r), Parse.concatenate(z));
	}

	public static void verifySchnorrSignature2(final EcCurve curve, final MessageDigest md, final EcPoint publicKey, byte[] message, byte[] signature) throws SignatureException
	{
		byte[][] sePair = Parse.splitArrays(signature);
		final byte[][] rParts =  Parse.splitArrays(sePair[0]);
		EcPoint r = new EcPoint(new BigInteger(1, rParts[0]), new BigInteger(1, rParts[1]));
		final BigInteger z = new BigInteger(1, Parse.splitArrays(sePair[1])[0]);
		
		
		// Compute e as hash(R, Y, m)
		byte[] challenge = Parse.concatenate(Parse.concatenate(r), Parse.concatenate(publicKey), message);
		BigInteger c = new BigInteger(1, md.digest(challenge));
		
		
		final EcPoint gZ = curve.multiply(curve.getG(), z);
		final EcPoint yC = curve.multiply(publicKey, BigInteger.ZERO.subtract(c));
		final EcPoint rv = curve.addPoints(gZ, yC);
		
		
		if (r.equals(rv))
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

		final MessageDigest md = MessageDigest.getInstance("SHA-512");
		
		final BigInteger privateSigningKey = RandomNumberGenerator.generateRandomPositiveInteger(fieldModulus);
		final EcPoint publicVerificationKey = curve.multiply(generator, privateSigningKey);
		
		byte[] message = "Hello World!".getBytes(Charsets.UTF_8);
		byte[] signature = sign1(curve, md, privateSigningKey, publicVerificationKey, message);
		
		verifySchnorrSignature1(curve, md, publicVerificationKey, message, signature);
		
		System.out.println("Verified signature!");
		
		//verifySchnorrSignature1(curve, md, publicVerificationKey, "Wrong message".getBytes(), signature);
		
		thresholdSchnorr();
	}
	
	
	
	public static void thresholdSchnorr() throws NoSuchAlgorithmException, SignatureException
	{
		// Static fields
		final  EcCurve curve = CommonConfiguration.CURVE;
		final EcPoint generator = curve.getG();
		final BigInteger fieldModulus = curve.getR();

		final MessageDigest md = MessageDigest.getInstance("SHA-512");
		
		
		
		final int threshold = 3;
		final int numShares = 5;
		
		final BigInteger[] coefficients = Shamir.generateCoefficients(threshold);
		final ShamirShare[] shares = Shamir.generateShares(coefficients, numShares);
		
		final EcPoint[] feldmanValues = Shamir.generateFeldmanValues(coefficients);
		final EcPoint[] shareholderPublicKeys = Shamir.computeSharePublicKeys(feldmanValues, numShares);
		
		// The main private/public key pair
		final EcPoint publicKey = Shamir.computeSharePublicKey(feldmanValues, 0);
		final BigInteger privateKey = coefficients[0];
		
		/****************************************************************************/
		
		// Everything is initialized, do sanity check withh public and private key

		
		byte[] message = "Hello World!".getBytes(Charsets.UTF_8);
		byte[] signature = sign2(curve, md, privateKey, publicKey, message);
		
		verifySchnorrSignature2(curve, md, publicKey, message, signature);
		System.out.println("Verified threshold signature 1!");
		
		/****************************************************************************/

		// Start the distributed signing by creating commitments
		
		SortedMap<BigInteger, NonceCommitment> commitments = new TreeMap<>();
		for (int i = 1; i < 5; i++) {
			commitments.put(BigInteger.valueOf(i), NonceCommitment.generateCommitment(curve));
		}
		
		System.out.println(commitments.keySet().toString());
		
		for (BigInteger index : commitments.keySet()) {
			BigInteger coefficient = Polynomials.computeLagrange(commitments.keySet().toArray(new BigInteger[commitments.size()]), index, curve.getR());
			System.out.println(index.toString() + " " + coefficient.toString());
		}
		
		// Create M || B
		byte[] combinedString = message.clone();
		for (final BigInteger index : commitments.keySet()) {
			byte[] tuple = Parse.concatenate(index, commitments.get(index).getgE().getX(), commitments.get(index).getgE().getY(), commitments.get(index).getgD().getX(), commitments.get(index).getgD().getY());
			combinedString = Parse.concatenate(combinedString, tuple);
		}
		
		// Compute R from multiplying each Ri
		EcPoint R = EcPoint.pointAtInfinity;
		for (final BigInteger index : commitments.keySet()) {
			
			final EcPoint Di = new EcPoint(commitments.get(index).getgD().getX(), commitments.get(index).getgD().getY());
			
			final EcPoint Ei = new EcPoint(commitments.get(index).getgE().getX(), commitments.get(index).getgE().getY());
			final BigInteger Pi = new BigInteger(1, md.digest(Parse.concatenate(index.toByteArray(), combinedString))).mod(curve.getR());
			
			final EcPoint EiPi = CommonConfiguration.CURVE.multiply(Ei, Pi);
			
			final EcPoint Ri = CommonConfiguration.CURVE.addPoints(Di, EiPi);
			
			// Sum up the Ris
			R = CommonConfiguration.CURVE.addPoints(R, Ri);
		}
		
		
		// Compute challenge c = H(R, Y, m)
		byte[] challenge = Parse.concatenate(Parse.concatenate(R), Parse.concatenate(publicKey), message);
		final BigInteger c = new BigInteger(1, md.digest(challenge));
		
		// Compute each share of the signature zi = di + ei*pi + Li
		SortedMap<BigInteger, BigInteger> shareContributions = new TreeMap<>();
		for (BigInteger index : commitments.keySet()) {
			final BigInteger si = shares[index.intValue()-1].getY();
			final BigInteger ei = commitments.get(index).getE();
			final BigInteger di = commitments.get(index).getD();
			final BigInteger pi = new BigInteger(1, md.digest(Parse.concatenate(index.toByteArray(), combinedString))).mod(curve.getR());
			final BigInteger coefficient = Polynomials.computeLagrange(commitments.keySet().toArray(new BigInteger[commitments.size()]), index, curve.getR());
		
			final BigInteger zi = ((di.add(ei.multiply(pi))).add(coefficient.multiply(si).multiply(c))).mod(curve.getR());
			shareContributions.put(index, zi);
		}
		
		System.out.println(shareContributions.toString());
		
		// Compute sum of all zs
		BigInteger sum = BigInteger.ZERO;
		for (BigInteger index : shareContributions.keySet()) {
			sum = sum.add(shareContributions.get(index)).mod(curve.getR());
		}
		
		final byte[] thresholdSig = Parse.concatenate(Parse.concatenate(R), Parse.concatenate(sum));
		
		verifySchnorrSignature2(curve, md, publicKey, message, thresholdSig);
		System.out.println("Verified threshold signature 2!");
	}
	
}
