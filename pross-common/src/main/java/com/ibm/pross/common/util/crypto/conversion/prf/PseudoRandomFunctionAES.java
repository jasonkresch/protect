package com.ibm.pross.common.util.crypto.conversion.prf;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.macs.CMac;
import org.bouncycastle.crypto.params.KeyParameter;

public class PseudoRandomFunctionAES extends PseudoRandomFunction {

	public static final int AES_BLOCK_SIZE = 16;
	
	private final CMac cipherMac;

	public PseudoRandomFunctionAES(final PrfKey key)  {
		super(key);

		// Create CMAC instance based on AES
		final BlockCipher cipher = new AESEngine();
	    this.cipherMac = new CMac(cipher);
	    
	    // Initialize with key
	    final KeyParameter params = new KeyParameter(key.getKeyBytes());
	    cipherMac.init(params);
	}

	@Override
	public byte[] computePrf(byte[] input) {
		
		final byte[] output = new byte[32];
		
		// Generate first block of output
		this.cipherMac.update(input, 0, input.length);
		this.cipherMac.doFinal(output, 0);
		
		// Generate second block of output using "feedback mode"
		this.cipherMac.update(output, 0, AES_BLOCK_SIZE);
		this.cipherMac.doFinal(output, AES_BLOCK_SIZE);
		
		return output;
	}

}
