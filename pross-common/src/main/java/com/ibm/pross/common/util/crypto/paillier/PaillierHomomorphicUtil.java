package com.ibm.pross.common.util.crypto.paillier;

import java.math.BigInteger;

import com.ibm.pross.common.util.Exponentiation;

public class PaillierHomomorphicUtil {

	public static BigInteger addCiphertexts(final PaillierPublicKey encryptionKey, final BigInteger c1, final BigInteger c2)
	{
		final BigInteger sum = c1.multiply(c2).mod(encryptionKey.getNSquared());
		return sum;
	}
	
	public static BigInteger subtractCiphertexts(final PaillierPublicKey encryptionKey, final BigInteger c1, final BigInteger c2)
	{
		final BigInteger negated = Exponentiation.modInverse(c2, encryptionKey.getNSquared());
		return addCiphertexts(encryptionKey, c1, negated);
	}
	
	public static BigInteger addConstant(final PaillierPublicKey encryptionKey, final BigInteger c1, final BigInteger constant)
	{
		final BigInteger gToM = Exponentiation.modPow(encryptionKey.getG(), constant, encryptionKey.getNSquared());
		return addCiphertexts(encryptionKey, c1, gToM);
	}

	public static BigInteger subtractConstant(final PaillierPublicKey encryptionKey, final BigInteger c1, final BigInteger constant)
	{
		final BigInteger negated = encryptionKey.getNSquared().subtract(constant);
		return addConstant(encryptionKey, c1, negated);
	}
	
	public static BigInteger multiplyConstant(final PaillierPublicKey encryptionKey, final BigInteger c1, final BigInteger constant)
	{
		final BigInteger product = Exponentiation.modPow(c1, constant, encryptionKey.getNSquared());
		return product;
	}
	
	public static BigInteger divideConstant(final PaillierPublicKey encryptionKey, final BigInteger c1, final BigInteger constant)
	{
		final BigInteger negated = Exponentiation.modInverse(constant, encryptionKey.getNSquared());
		return multiplyConstant(encryptionKey, c1, negated);
	}
}
