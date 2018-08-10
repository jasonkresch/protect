/*
 * Copyright (c) IBM Corporation 2018. All Rights Reserved.
 * Project name: pross
 * This project is licensed under the MIT License, see LICENSE.
 */

package com.ibm.pross.common.util.serialization;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

public class Parse {

	/**
	 * Generates a deterministic serialization of a group of byte arrays
	 * 
	 * @param integers
	 * @return
	 * @throws IOException
	 */
	public static byte[] concatenate(BigInteger... integers) {
		try {
			ByteArrayOutputStream bos = new ByteArrayOutputStream();
			DataOutputStream dos = new DataOutputStream(bos);
			for (BigInteger i : integers) {
				byte[] encoded = i.toByteArray();
				dos.writeInt(encoded.length);
				dos.write(encoded);
			}
			dos.flush();
			bos.flush();
			return bos.toByteArray();
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
	}

	/**
	 * Generates a deterministic serialization of a group of byte arrays
	 * 
	 * @param arrays
	 * @return
	 * @throws IOException
	 */
	public static byte[] concatenate(final byte[]... arrays) {
		try {
			final ByteArrayOutputStream bos = new ByteArrayOutputStream();
			final DataOutputStream dos = new DataOutputStream(bos);
			for (byte[] array : arrays) {
				dos.writeInt(array.length);
				dos.write(array);
			}

			dos.flush();
			bos.flush();
			return bos.toByteArray();
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
	}

	/**
	 * Splits an array (generated from concatenate()) into its constituent
	 * tokens.
	 * 
	 * @see concatenate
	 * 
	 * @param concatenated
	 *            The single byte-array produced from a concatenation of arrays
	 * @return The original arrays that were input into the concatenation to
	 *         produce a single array
	 */
	public static byte[][] splitArrays(final byte[] concatenated) {

		List<byte[]> arrays = new ArrayList<>();

		// Iterate through and gather the arrays
		final ByteArrayInputStream bis = new ByteArrayInputStream(concatenated);
		final DataInputStream dis = new DataInputStream(bis);

		try {
			while (true) {
				int arraySize = dis.readInt();
				byte[] array = new byte[arraySize];
				dis.read(array);

				arrays.add(array);

				if (dis.available() == 0)
					break;
			}
		} catch (IOException e) {
			throw new RuntimeException(e);
		}

		byte[][] split = new byte[arrays.size()][];
		for (int i = 0; i < arrays.size(); i++) {
			split[i] = arrays.get(i);
		}
		return split;
	}
}
