package com.ibm.pross.server.dkgnew;

import java.math.BigInteger;
import java.security.Security;
import java.util.AbstractMap.SimpleEntry;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map.Entry;
import java.util.Set;
import java.util.SortedSet;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;

import com.ibm.pross.common.util.crypto.ecc.EcPoint;
import com.ibm.pross.common.util.shamir.Polynomials;
import com.ibm.pross.common.util.shamir.ShamirShare;
import com.ibm.pross.server.dkgnew.AlertLog.ErrorCondition;

public class DkgNewTest {

	@BeforeClass
	public static void setupBefore() {
		Security.addProvider(new BouncyCastleProvider());
	}

	private static void printErrors(final List<DkgNewShareholder> shareholders)
	{
		for (DkgNewShareholder shareholder : shareholders)
		{
			System.out.println("Errors reported by shareholder with index = " + shareholder.getIndex() + ":");
			for (Entry<SimpleEntry<Integer, Integer>, ErrorCondition> alert : shareholder.alertLog.getAlerts().entrySet())
			{
				int reportedShareholder = alert.getKey().getValue();
				ErrorCondition error = alert.getValue();
				System.out.println("   Shareholder[" + reportedShareholder + "] committed a " + error + " error");
			}
		}
	}
	
	@Test
	public void testPedersenValidationAllGood() throws InterruptedException {

		// Create channel
		final FifoAtomicBroadcastChannel channel = new FifoAtomicBroadcastChannel();

		// Define parameters
		final int n = 7;
		final int k = 3;
		final int f = 2;

		// Create shareholders
		final List<DkgNewShareholder> shareholders = new ArrayList<>();
		for (int i = 0; i < n; i++) {
			final DkgNewShareholder shareholder = new DkgNewShareholder(shareholders, channel, i, n, k, f, true);
			shareholders.add(shareholder);
			channel.registerShareholder(shareholder);
		}

		// Broadcast messages
		for (int i = 0; i < n; i++) {
			shareholders.get(i).broadcastShareContribtions();
		}

		// Wait messages
		for (int i = 0; i < n; i++) {
			shareholders.get(i).waitForQual();
		}

		// Ensure qual sets are identical
		final SortedSet<Integer> expectedQual = shareholders.get(0).getQualSet();
		for (int i = 0; i < n; i++) {
			System.out.println(i + ": qual = " + shareholders.get(i).getQualSet());
			Assert.assertEquals(expectedQual, shareholders.get(i).getQualSet());
		}

		// Ensure share consistency with interpolation
		final Set<ShamirShare> shares1 = new HashSet<>();
		final Set<ShamirShare> shares2 = new HashSet<>();
		for (int i = 0; i < n; i++) {
			System.out.println(i + ": share = " + shareholders.get(i).getShare1());
			shares1.add(shareholders.get(i).getShare1());
			shares2.add(shareholders.get(i).getShare2());
		}

		for (int i = 1; i <= n; i++) {
			final BigInteger y1 = Polynomials.interpolateComplete(shares1, k, i);
			System.out.println(y1);
			Assert.assertEquals(y1, shareholders.get(i - 1).getShare1().getY());

			final BigInteger y2 = Polynomials.interpolateComplete(shares2, k, i);
			Assert.assertEquals(y2, shareholders.get(i - 1).getShare2().getY());
		}

		// Wait for completion
		for (int i = 0; i < n; i++) {
			shareholders.get(i).waitForPublicKeys();
		}

		// Compute expected public key for the overall secret
		final BigInteger secret = Polynomials.interpolateComplete(shares1, k, 0);
		final EcPoint publicKey = DkgNewShareholder.curve.multiply(DkgNewShareholder.g, secret);
		System.out.println("Determined public key: " + publicKey);

		// TODO: work on this, right now it is for zero?
		for (int i = 0; i < n; i++) {
			System.out.println("For i = " + i);
			System.out.println(shareholders.get(i).getSecretPublicKey());
			Assert.assertEquals(publicKey, shareholders.get(i).getSecretPublicKey());
		}
		
		// Stop shareholder threads
		for (int i = 0; i < n; i++) {
			shareholders.get(i).stop();
		}
		
		printErrors(shareholders);
	}

	@Test
	public void testPedersenValidationOneSlowShareholder() throws Exception {

		// Create channel
		final FifoAtomicBroadcastChannel channel = new FifoAtomicBroadcastChannel();

		// Define parameters
		final int n = 7;
		final int k = 3;
		final int f = 2;

		// Create shareholders
		final List<DkgNewShareholder> shareholders = new ArrayList<>();
		for (int i = 0; i < n; i++) {
			final DkgNewShareholder shareholder = new DkgNewShareholder(shareholders, channel, i, n, k, f, true);
			shareholders.add(shareholder);
			channel.registerShareholder(shareholder);
		}

		// Broadcast messages
		for (int i = 1; i < n; i++) {
			shareholders.get(i).broadcastShareContribtions();
		}

		// Wait messages
		for (int i = 0; i < n; i++) {
			shareholders.get(i).waitForQual();
		}

		// Ensure qual sets are identical
		final SortedSet<Integer> expectedQual = shareholders.get(0).getQualSet();
		for (int i = 0; i < n; i++) {
			System.out.println(i + ": qual = " + shareholders.get(i).getQualSet());
			Assert.assertEquals(expectedQual, shareholders.get(i).getQualSet());
		}

		// Ensure share consistency with interpolation
		final Set<ShamirShare> shares1 = new HashSet<>();
		final Set<ShamirShare> shares2 = new HashSet<>();
		for (int i = 0; i < n; i++) {
			System.out.println(i + ": share = " + shareholders.get(i).getShare1());
			shares1.add(shareholders.get(i).getShare1());
			shares2.add(shareholders.get(i).getShare2());
		}

		for (int i = 1; i <= n; i++) {
			final BigInteger y1 = Polynomials.interpolateComplete(shares1, k, i);
			System.out.println(y1);
			Assert.assertEquals(y1, shareholders.get(i - 1).getShare1().getY());

			final BigInteger y2 = Polynomials.interpolateComplete(shares2, k, i);
			Assert.assertEquals(y2, shareholders.get(i - 1).getShare2().getY());
		}

		// Wait for completion
		for (int i = 0; i < n; i++) {
			shareholders.get(i).waitForPublicKeys();
		}

		// Compute expected public key for the overall secret
		final BigInteger secret = Polynomials.interpolateComplete(shares1, k, 0);
		final EcPoint publicKey = DkgNewShareholder.curve.multiply(DkgNewShareholder.g, secret);
		System.out.println("Determined public key: " + publicKey);

		// TODO: work on this, right now it is for zero?
		for (int i = 0; i < n; i++) {
			System.out.println("For i = " + i);
			System.out.println(shareholders.get(i).getSecretPublicKey());
			Assert.assertEquals(publicKey, shareholders.get(i).getSecretPublicKey());
		}
		
		// Stop shareholder threads
		for (int i = 0; i < n; i++) {
			shareholders.get(i).stop();
		}
		
		printErrors(shareholders);
	}

	@Test
	public void testPedersenValidationOneBadShareholder() throws InterruptedException {

		// Create channel
		final FifoAtomicBroadcastChannel channel = new FifoAtomicBroadcastChannel();

		// Define parameters
		final int n = 7;
		final int k = 3;
		final int f = 2;

		final List<DkgNewShareholder> shareholders = new ArrayList<>();

		// Create bad shareholder
		final DkgNewShareholder badShareholder = new DkgNewShareholder(shareholders, channel, 0, n, k, f, false);
		shareholders.add(badShareholder);
		channel.registerShareholder(badShareholder);

		// Create good shareholders
		for (int i = 1; i < n; i++) {
			final DkgNewShareholder shareholder = new DkgNewShareholder(shareholders, channel, i, n, k, f, true);
			shareholders.add(shareholder);
			channel.registerShareholder(shareholder);
		}

		// Broadcast messages
		for (DkgNewShareholder shareholder : shareholders) {
			shareholder.broadcastShareContribtions();
		}

		// Wait messages
		for (int i = 0; i < n; i++) {
			shareholders.get(i).waitForQual();
		}

		// Ensure qual sets are identical
		final SortedSet<Integer> expectedQual = shareholders.get(0).getQualSet();
		for (int i = 0; i < n; i++) {
			System.out.println(i + ": qual = " + shareholders.get(i).getQualSet());
			Assert.assertEquals(expectedQual, shareholders.get(i).getQualSet());
		}

		// Ensure share consistency with interpolation
		final Set<ShamirShare> shares1 = new HashSet<>();
		final Set<ShamirShare> shares2 = new HashSet<>();
		for (int i = 0; i < n; i++) {
			System.out.println(i + ": share = " + shareholders.get(i).getShare1());
			shares1.add(shareholders.get(i).getShare1());
			shares2.add(shareholders.get(i).getShare2());
		}

		for (int i = 1; i <= n; i++) {
			final BigInteger y1 = Polynomials.interpolateComplete(shares1, k, i);
			System.out.println(y1);
			Assert.assertEquals(y1, shareholders.get(i - 1).getShare1().getY());

			final BigInteger y2 = Polynomials.interpolateComplete(shares2, k, i);
			Assert.assertEquals(y2, shareholders.get(i - 1).getShare2().getY());
		}

		// Wait for completion
		for (int i = 0; i < n; i++) {
			shareholders.get(i).waitForPublicKeys();
		}

		// Compute expected public key for the overall secret
		final BigInteger secret = Polynomials.interpolateComplete(shares1, k, 0);
		final EcPoint publicKey = DkgNewShareholder.curve.multiply(DkgNewShareholder.g, secret);
		System.out.println("Determined public key: " + publicKey);

		// TODO: work on this, right now it is for zero?
		for (int i = 0; i < n; i++) {
			System.out.println("For i = " + i);
			System.out.println(shareholders.get(i).getSecretPublicKey());
			Assert.assertEquals(publicKey, shareholders.get(i).getSecretPublicKey());
		}
		
		// Stop shareholder threads
		for (int i = 0; i < n; i++) {
			shareholders.get(i).stop();
		}

		printErrors(shareholders);
	}

	// TODO: Test a valid rebuttal being sent to get back into the qual set
	
	// TODO: Test a member of the qual set not sending his y_i = g^x_i
	
	// TODO: Don't start enough shareholders
	
	// TODO: Start only enough shareholders
	
	// TODO: Have maximum number of faults
	
	// TODO: Have some shareholders crash at different stages
	
	// TODO: Make test with random crashes (up to maximum), try many iterations (or enumerate them all)
	
	// TODO: Once every edge/corner case, ensure complete code coverage
	
}
