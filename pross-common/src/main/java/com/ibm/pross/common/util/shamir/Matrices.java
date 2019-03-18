package com.ibm.pross.common.util.shamir;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.List;

import com.ibm.pross.common.DerivationResult;
import com.ibm.pross.common.config.CommonConfiguration;
import com.ibm.pross.common.util.Exponentiation;
import com.ibm.pross.common.util.crypto.ecc.EcCurve;
import com.ibm.pross.common.util.crypto.ecc.EcPoint;

/**
 * Contains methods for for matrix inversion from: https://www.sanfoundry.com/java-program-find-inverse-matrix/
 * Adapted to use BigIntegers and field arithmetic
 */
public class Matrices {

	// Static fields
	final public static EcCurve curve = CommonConfiguration.CURVE;
	final public static BigInteger r = curve.getR();
	final public static EcPoint G = curve.getG();

	public static BigInteger[][] generateSquareVandermondeMatrix(final int t) {
		
		// Allocate t rows
		final BigInteger[][] matrix = new BigInteger[t][];

		for (int i = 0; i < t; i++) {
			// Create new row of size t
			matrix[i] = new BigInteger[t];
			BigInteger base = BigInteger.valueOf(i + 1);
			for (int j = 0; j < t; j++) {
				matrix[i][j] = Exponentiation.modPow(base, BigInteger.valueOf(j), r);
			}
		}

		return matrix;
	}
	
	public static BigInteger[][] generateCustomVandermondeFormMatrix(final BigInteger[] xCoords) {
		
		final int t = xCoords.length;
		
		// Allocate t rows
		final BigInteger[][] matrix = new BigInteger[t][];

		for (int i = 0; i < t; i++) {
			// Create new row of size t
			matrix[i] = new BigInteger[t];
			BigInteger base = xCoords[i];
			for (int j = 0; j < t; j++) {
				matrix[i][j] = Exponentiation.modPow(base, BigInteger.valueOf(j), r);
			}
		}

		return matrix;
	}
	
	public static BigInteger[] multiplyShareVector(final BigInteger[][] matrix, final List<ShamirShare> shares)
	{
		final int t = matrix.length;
		final BigInteger[] result = new BigInteger[t];
		
		for (int i = 0; i < t; i++)
		{
			result[i] = BigInteger.ZERO;
			
			// Loop to compute sum
			for (int j = 0; j < t; j++)
			{
				result[i] = add(result[i], mul(matrix[i][j], shares.get(j).getY()));
			}
		}
		
		return result;
	}
	
	public static EcPoint[] multiplyPointVector(final BigInteger[][] matrix, final List<DerivationResult> responses)
	{
		final int t = matrix.length;
		final EcPoint[] result = new EcPoint[t];
		
		for (int i = 0; i < t; i++)
		{
			result[i] = EcPoint.pointAtInfinity;
			
			// Loop to compute sum
			for (int j = 0; j < t; j++)
			{
				result[i] = curve.addPoints(result[i], curve.multiply(responses.get(j).getDerivedSharePoint(), matrix[i][j]));
			}
		}
		
		return result;
	}
	
	public static BigInteger[][] generateInvertedCustomVandermondeFormMatrix(final BigInteger[] xCoords) {
		
		// Create VandermondeMatrix
		final BigInteger[][] vandermondeMatrix = generateCustomVandermondeFormMatrix(xCoords);

		// Invert it
		return invert(vandermondeMatrix);
	}
	
	public static BigInteger[][] generateInvertedVandermondeMatrix(final int t) {
		// Create VandermondeMatrix
		final BigInteger[][] vandermondeMatrix = generateSquareVandermondeMatrix(t);

		// Invert it
		return invert(vandermondeMatrix);
	}

	// Return (a*b)
	protected static BigInteger mul(BigInteger a, BigInteger b) {
		if ((a == null) || (b == null)) {
			return BigInteger.ZERO;
		}
			
		return a.multiply(b).mod(r);
	}

	// Return (a/b)
	protected static BigInteger div(BigInteger a, BigInteger b) {
		return a.multiply(b.modInverse(r)).mod(r);
	}

	// Return (a+b)
	protected static BigInteger add(BigInteger a, BigInteger b) {
		return a.add(b).mod(r);
	}

	// Return (a-b)
	protected static BigInteger sub(BigInteger a, BigInteger b) {
		if (a == null)
			a = BigInteger.ZERO;
		return a.subtract(b).mod(r);
	}

	public static BigInteger[][] invert(BigInteger a[][]) {
		int n = a.length;
		BigInteger x[][] = new BigInteger[n][n];
		BigInteger b[][] = new BigInteger[n][n];
		int index[] = new int[n];
		for (int i = 0; i < n; ++i)
			b[i][i] = BigInteger.ONE;

		// Transform the matrix into an upper triangle
		gaussian(a, index);

		// Update the matrix b[i][j] with the ratios stored
		for (int i = 0; i < n - 1; ++i)
			for (int j = i + 1; j < n; ++j)
				for (int k = 0; k < n; ++k)
					b[index[j]][k] = sub(b[index[j]][k], mul(a[index[j]][i], b[index[i]][k]));

		// Perform backward substitutions
		for (int i = 0; i < n; ++i) {
			x[n - 1][i] = div(b[index[n - 1]][i], a[index[n - 1]][n - 1]);
			for (int j = n - 2; j >= 0; --j) {
				x[j][i] = b[index[j]][i];
				for (int k = j + 1; k < n; ++k) {
					x[j][i] = sub(x[j][i], mul(a[index[j]][k], x[k][i]));
				}
				x[j][i] = div(x[j][i], a[index[j]][j]);
			}
		}
		return x;
	}

// Method to carry out the partial-pivoting Gaussian
// elimination.  Here index[] stores pivoting order.

	protected static void gaussian(BigInteger a[][], int index[]) {
		int n = index.length;
		BigInteger c[] = new BigInteger[n];

		// Initialize the index
		for (int i = 0; i < n; ++i)
			index[i] = i;

		// Find the rescaling factors, one from each row
		for (int i = 0; i < n; ++i) {
			BigInteger c1 = BigInteger.ZERO;
			for (int j = 0; j < n; ++j) {
				BigInteger c0 = a[i][j].mod(r);
				if (c0.compareTo(c1) > 0)
					c1 = c0;
			}
			c[i] = c1;
		}

		// Search the pivoting element from each column
		int k = 0;
		for (int j = 0; j < n - 1; ++j) {
			BigInteger pi1 = BigInteger.ZERO;
			for (int i = j; i < n; ++i) {
				BigInteger pi0 = a[index[i]][j].mod(r);
				pi0 = div(pi0, c[index[i]]);
				if (pi0.compareTo(pi1) > 0) {
					pi1 = pi0;
					k = i;
				}
			}

			// Interchange rows according to the pivoting order
			int itmp = index[j];
			index[j] = index[k];
			index[k] = itmp;
			for (int i = j + 1; i < n; ++i) {
				BigInteger pj = div(a[index[i]][j], a[index[j]][j]);

				// Record pivoting ratios below the diagonal
				a[index[i]][j] = pj;

				// Modify other elements accordingly
				for (int l = j + 1; l < n; ++l)
					a[index[i]][l] = sub(a[index[i]][l], mul(pj, a[index[j]][l]));
			}
		}
	}

	public static void printMatrix(final BigInteger[][] matrix) {
		System.out.print("{  ");
		for (int i = 0; i < matrix.length; i++) {
			if (i == matrix.length - 1)
				System.out.print(Arrays.toString(matrix[i]));
			else
				System.out.println(Arrays.toString(matrix[i]));
			System.out.print("   ");
		}
		System.out.println("}");
	}

	public static void main(String args[]) {
		long start = System.nanoTime();
		final BigInteger[][] matrix = generateSquareVandermondeMatrix(10);
		long end = System.nanoTime();
		System.out.println(end - start);

		printMatrix(matrix);

		final BigInteger[][] invertedVandermonde = invert(matrix);

		printMatrix(invertedVandermonde);

		final BigInteger[][] restoredVandermonde = invert(invertedVandermonde);

		printMatrix(restoredVandermonde);
	}
}
