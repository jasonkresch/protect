package com.ibm.pross.common.util.crypto.rsa.threshold.sign.example;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import com.ibm.pross.common.util.crypto.rsa.threshold.sign.client.RsaDealingClient;
import com.ibm.pross.common.util.crypto.rsa.threshold.sign.client.RsaSignatureClient;
import com.ibm.pross.common.util.crypto.rsa.threshold.sign.exceptions.BadArgumentException;
import com.ibm.pross.common.util.crypto.rsa.threshold.sign.exceptions.BelowThresholdException;
import com.ibm.pross.common.util.crypto.rsa.threshold.sign.exceptions.SecretRecoveryException;
import com.ibm.pross.common.util.crypto.rsa.threshold.sign.exceptions.UserNotFoundException;
import com.ibm.pross.common.util.crypto.rsa.threshold.sign.server.RsaSignatureServer;

/**
 * Runnable class that exhibits functionality of the protocol.
 * 
 * This prototype is based on: "Practical Threshold Signatures" by Victor Shoup
 * http://www.iacr.org/archive/eurocrypt2000/1807/18070209-new.pdf
 */
public class Driver {

	public static void main(String args[]) throws BadArgumentException, BelowThresholdException,
			SecretRecoveryException, UserNotFoundException, NoSuchAlgorithmException, InvalidKeyException, InvalidKeySpecException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {

		System.out.println("Dealing secret to the servers...");

		// Create servers
		final int serverCount = 18;
		final int threshold = 10;
		RsaSignatureServer[] servers = RsaSignatureServer.initializeServers(serverCount);

		// Setup dealer
		RsaDealingClient dealer = new RsaDealingClient(servers, threshold);

		// Register user a secret to be held in trust of the servers
		final String keyName = "joe";
		final byte[] toBeSigned = "my message".getBytes(StandardCharsets.UTF_8);
		byte[] testSignature = dealer.registerWithServers(keyName, toBeSigned);

		System.out.println("Registration complete!");
		System.out.println();
		
		System.out.println("Signature     = " + Arrays.toString(testSignature));
		System.out.println("Signature Int = " + new BigInteger(1, testSignature));
		
		System.out.println();
		System.out.println("Recovering secret from the servers...");

		// Use the client to recover the signature from the servers
		RsaSignatureClient client = new RsaSignatureClient(servers, threshold);
		BigInteger recoveredSignature = client.recoverSignature(keyName, toBeSigned);
		System.out.println("Secret recovery complete!");

		System.out.println();
		System.out.println("signature     = " + Arrays.toString(recoveredSignature.toByteArray()));
		System.out.println("signature int = " + recoveredSignature);
		System.out.println();

		if (new BigInteger(1, testSignature).equals(recoveredSignature)) {
			System.out.println("Signatures match!");
		} else {
			System.err.println("Signature mismatch!");
		}
		
		System.out.println("Done.");
	}

}
