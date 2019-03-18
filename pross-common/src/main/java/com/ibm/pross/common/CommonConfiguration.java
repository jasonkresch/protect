/*
 * Copyright (c) IBM Corporation 2018. All Rights Reserved.
 * Project name: pross
 * This project is licensed under the MIT License, see LICENSE.
 */

package com.ibm.pross.common;

import com.ibm.pross.common.util.crypto.ecc.EcCurve;
import com.ibm.pross.common.util.crypto.ecc.EcCurveBc;
import com.ibm.pross.common.util.crypto.ecc.EcPoint;

/**
 * This class defines common configuration for a given setting for TOPPSS
 */
public class CommonConfiguration {

	/**
	 * The order of this curve should be at least 2**(2 * SECURITY_LEVEL_BITS)
	 *
	 * As defined in:
	 * http://csrc.nist.gov/groups/ST/toolkit/documents/dss/NISTReCur.pdf the
	 * following curves provide the following corresponding security levels
	 * 
	 * <pre>
	 *   Symmetric Key Equivalent   Example    Prime Field
	 *   ========================   ========   ===========
	 *   80-bits                    SKIPJACK   NIST P-192
	 *   112-bits                   3DES       NIST P-224
	 *   128-bits                   AES-128    NIST P-256
	 *   192-bits                   AES-192    NIST P-384
	 *   256-bits                   AES-256    NIST P-521
	 * </pre>
	 */

	// This implementation is significantly faster
	public static final EcCurve CURVE = EcCurveBc.createByName(EcCurve.secp256r1.getName());

	// Generators (from hashing)
	public static final EcPoint g = CURVE.getPointHasher().hashToCurve(new byte[] { 0x01 });
	public static final EcPoint h = CURVE.getPointHasher().hashToCurve(new byte[] { 0x02 });

	// Default hash algorithm
	public static final String HASH_ALGORITHM = "SHA-512";
	
	// Default signature algorithms for different key types
	public final static String EC_SIGNATURE_ALGORITHM = "SHA512withECDSA";
	public final static String ED_SIGNATURE_ALGORITHM = "NONEwithEdDSA";
	public final static String RSA_SIGNATURE_ALGORITHM = "SHA512withRSA";
}
