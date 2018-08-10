/*
 * Copyright (c) IBM Corporation 2018. All Rights Reserved.
 * Project name: pross
 * This project is licensed under the MIT License, see LICENSE.
 */

package com.ibm.pross.common.util.crypto.ecc;

import java.util.Map;
import java.util.Map.Entry;
import java.util.concurrent.ConcurrentHashMap;

public class CurveLookupMap {

	// Provides mapping from curve names to the curve itself
	private static final Map<String, EcCurve> NAME_TO_CURVE_MAP = new ConcurrentHashMap<>();

	// Provides mapping from curve OID to the curve itself
	private static final Map<String, EcCurve> OID_TO_CURVE_MAP = new ConcurrentHashMap<>();

	// Provides mapping from the curve to the curve name
	private static final Map<EcCurve, String> CURVE_TO_NAME_MAP = new ConcurrentHashMap<>();

	// Provides mapping from the curve to the curve oid
	private static final Map<EcCurve, String> CURVE_TO_OID_MAP = new ConcurrentHashMap<>();

	static {
		// Populate name map
		NAME_TO_CURVE_MAP.put("secp256r1", EcCurve.secp256r1);
		NAME_TO_CURVE_MAP.put("secp384r1", EcCurve.secp384r1);
		NAME_TO_CURVE_MAP.put("secp521r1", EcCurve.secp521r1);

		// Populate oid map

		// iso(1) member-body(2) us(840) ansi-X9-62(10045) curves(3) prime(1)
		// prime256v1(7)
		OID_TO_CURVE_MAP.put("1.2.840.10045.3.1.7", EcCurve.secp256r1);

		// iso(1) identified-organization(3) certicom(132) curve(0)
		// ansip384r1(34)
		OID_TO_CURVE_MAP.put("1.3.132.0.34", EcCurve.secp384r1);

		// iso(1) identified-organization(3) certicom(132) curve(0)
		// ansip521r1(35)
		OID_TO_CURVE_MAP.put("1.3.132.0.35", EcCurve.secp521r1);

		// Populate reverse name map
		for (Entry<String, EcCurve> entry : NAME_TO_CURVE_MAP.entrySet()) {
			CURVE_TO_NAME_MAP.put(entry.getValue(), entry.getKey());
		}

		// Populate reverse oid map
		for (Entry<String, EcCurve> entry : OID_TO_CURVE_MAP.entrySet()) {
			CURVE_TO_OID_MAP.put(entry.getValue(), entry.getKey());
		}

	}

	/**
	 * Returns the elliptic curve for a given curve name or null if not found
	 * 
	 * @param name
	 * @return
	 */
	public static EcCurve getCurveByName(String name) {
		return NAME_TO_CURVE_MAP.get(name);
	}

	/**
	 * Returns the elliptic curve for a given curve OID or null if not found
	 * 
	 * @param oid
	 * @return
	 */
	public static EcCurve getCurveByOid(String oid) {
		return OID_TO_CURVE_MAP.get(oid);
	}

	/**
	 * Returns the name for a given elliptic curve
	 * 
	 * @param curve
	 * @return
	 */
	public static String getCurveName(EcCurve curve) {
		return CURVE_TO_NAME_MAP.get(curve);
	}

	/**
	 * Returns the OID for a given elliptic curve
	 * 
	 * @param curve
	 * @return
	 */
	public static String getCurveOid(EcCurve curve) {
		return CURVE_TO_OID_MAP.get(curve);
	}

}
