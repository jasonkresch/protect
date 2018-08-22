/*
 * Copyright (c) IBM Corporation 2018. All Rights Reserved.
 * Project name: pross
 * This project is licensed under the MIT License, see LICENSE.
 */

package com.ibm.pross.common.util.serialization;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;

public class HexUtil {

	public static String binToHex(byte[] array)
	{
		return Hex.encodeHexString(array);
	}
	
	public static byte[] hexToBin(String hex) throws DecoderException
	{
		return Hex.decodeHex(hex.toCharArray());
	}
	
}
