package com.ibm.pross.server.app.avpss;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.util.AbstractMap.SimpleEntry;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.SortedSet;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;

import com.ibm.pross.common.util.crypto.ecc.EcPoint;
import com.ibm.pross.common.util.shamir.Polynomials;
import com.ibm.pross.common.util.shamir.ShamirShare;
import com.ibm.pross.server.app.ServerApplication;
import com.ibm.pross.server.app.avpss.AlertLog.ErrorCondition;
import com.ibm.pross.server.app.avpss.channel.FifoAtomicBroadcastChannelLocalImpl;

import bftsmart.reconfiguration.util.sharedconfig.KeyLoader;

public class ApvssTest {

	@BeforeClass
	public static void setupBefore() {
		Security.addProvider(new BouncyCastleProvider());
	}

	private static void printErrors(final List<ApvssShareholder> shareholders)
	{
		for (ApvssShareholder shareholder : shareholders)
		{
			System.out.println("Errors reported by shareholder with index = " + shareholder.getIndex() + ":");
			for (SimpleEntry<Integer, ErrorCondition> alert : shareholder.alertLog.getAlerts())
			{
				int reportedShareholder = alert.getKey();
				ErrorCondition error = alert.getValue();
				System.out.println("   Shareholder[" + reportedShareholder + "] committed a " + error + " error");
			}
		}
	}
	
	
	private final KeyLoader createKeyLoader(final int numServers, final int serverIndex) throws FileNotFoundException, NoSuchAlgorithmException, InvalidKeySpecException, IOException, CertificateException
	{
		final String baseDirectory = "config/server/";
		
		// Load keys
		final File keysDirectory = new File(baseDirectory, ServerApplication.SERVER_KEYS_DIRECTORY);
		return new KeyLoader(keysDirectory, numServers, serverIndex);
	}
	
	@Test
	public void testPedersenValidationAllGood() throws InterruptedException, FileNotFoundException, NoSuchAlgorithmException, InvalidKeySpecException, IOException, CertificateException {

		// Create channel
		final FifoAtomicBroadcastChannelLocalImpl channel = new FifoAtomicBroadcastChannelLocalImpl();

		// Define parameters
		final int n = 5;
		final int k = 3;
		
		// Create shareholders
		final List<ApvssShareholder> shareholders = new ArrayList<>();
		for (int i = 1; i <= n; i++) {
			final KeyLoader keyLoader = createKeyLoader(n, i);
			final ApvssShareholder shareholder = new ApvssShareholder("test", keyLoader, channel, i, n, k, true);
			shareholders.add(shareholder);
		}

		// Broadcast messages
		for (int i = 0; i < n; i++) {
			shareholders.get(i).start(true);
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
		final EcPoint publicKey = ApvssShareholder.curve.multiply(ApvssShareholder.g, secret);
		System.out.println("Determined public key: " + publicKey);

		// Ensure public key matches everyone's expectations
		for (int i = 0; i < n; i++) {
			System.out.println("For i = " + i);
			System.out.println(shareholders.get(i).getSecretPublicKey());
			Assert.assertEquals(publicKey, shareholders.get(i).getSecretPublicKey());
		}
		
		// Ensure everyone has the same public key set
		for (int i = 0; i <= n; i++)
		{
			final EcPoint ecPublicKey = shareholders.get(0).getSharePublicKey(i);
			for (ApvssShareholder shareholder : shareholders)
			{
				Assert.assertEquals(ecPublicKey, shareholder.getSharePublicKey(i));
			}
		}
		System.out.println("All shareholders have the same public keys");
		
		// Stop shareholder threads
		for (int i = 0; i < n; i++) {
			shareholders.get(i).stop();
		}
		
		printErrors(shareholders);
	}

	@Test
	public void testPedersenValidationOneSlowShareholder() throws Exception {

		// Create channel
		final FifoAtomicBroadcastChannelLocalImpl channel = new FifoAtomicBroadcastChannelLocalImpl();

		// Define parameters
		final int n = 5;
		final int k = 3;
		
		// Create shareholders
		final List<ApvssShareholder> shareholders = new ArrayList<>();
		for (int i = 1; i <= n; i++) {
			final KeyLoader keyLoader = createKeyLoader(n, i);
			final ApvssShareholder shareholder = new ApvssShareholder("test", keyLoader, channel, i, n, k, true);
			shareholders.add(shareholder);
		}

		// Broadcast messages
		shareholders.get(0).start(false);
		for (int i = 1; i < n; i++) {
			shareholders.get(i).start(true);
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
		final EcPoint publicKey = ApvssShareholder.curve.multiply(ApvssShareholder.g, secret);
		System.out.println("Determined public key: " + publicKey);

		// Ensure public key matches everyone's expectations
		for (int i = 0; i < n; i++) {
			System.out.println("For i = " + i);
			System.out.println(shareholders.get(i).getSecretPublicKey());
			Assert.assertEquals(publicKey, shareholders.get(i).getSecretPublicKey());
		}
		
		// Ensure everyone has the same public key set
		for (int i = 0; i <= n; i++)
		{
			final EcPoint ecPublicKey = shareholders.get(0).getSharePublicKey(i);
			for (ApvssShareholder shareholder : shareholders)
			{
				Assert.assertEquals(ecPublicKey, shareholder.getSharePublicKey(i));
			}
		}
		System.out.println("All shareholders have the same public keys");
		
		// Stop shareholder threads
		for (int i = 0; i < n; i++) {
			shareholders.get(i).stop();
		}
		
		printErrors(shareholders);
	}

	@Test
	public void testPedersenValidationOneBadShareholder() throws InterruptedException, FileNotFoundException, NoSuchAlgorithmException, InvalidKeySpecException, IOException, CertificateException {

		// Create channel
		final FifoAtomicBroadcastChannelLocalImpl channel = new FifoAtomicBroadcastChannelLocalImpl();

		// Define parameters
		final int n = 5;
		final int k = 3;
		
		// Create shareholders
		final List<ApvssShareholder> shareholders = new ArrayList<>();



		// Create bad shareholder
		final KeyLoader keyLoader1 = createKeyLoader(n, 1);
		final ApvssShareholder badShareholder = new ApvssShareholder("test", keyLoader1, channel, 1, n, k, false);
		shareholders.add(badShareholder);

		// Create good shareholders
		for (int i = 2; i <= n; i++) {
			final KeyLoader keyLoader = createKeyLoader(n, i);
			final ApvssShareholder shareholder = new ApvssShareholder("test", keyLoader, channel, i, n, k, true);
			shareholders.add(shareholder);
		}

		// Broadcast messages
		for (ApvssShareholder shareholder : shareholders) {
			shareholder.start(true);
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
		final EcPoint publicKey = ApvssShareholder.curve.multiply(ApvssShareholder.g, secret);
		System.out.println("Determined public key: " + publicKey);

		// Ensure public key matches everyone's expectations
		for (int i = 0; i < n; i++) {
			System.out.println("For i = " + i);
			System.out.println(shareholders.get(i).getSecretPublicKey());
			Assert.assertEquals(publicKey, shareholders.get(i).getSecretPublicKey());
		}
		
		// Ensure everyone has the same public key set
		for (int i = 0; i <= n; i++)
		{
			final EcPoint ecPublicKey = shareholders.get(0).getSharePublicKey(i);
			for (ApvssShareholder shareholder : shareholders)
			{
				Assert.assertEquals(ecPublicKey, shareholder.getSharePublicKey(i));
			}
		}
		System.out.println("All shareholders have the same public keys");
		
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
