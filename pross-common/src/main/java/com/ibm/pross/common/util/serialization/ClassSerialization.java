/*
 * Copyright (c) IBM Corporation 2018. All Rights Reserved.
 * Project name: pross
 * This project is licensed under the MIT License, see LICENSE.
 */

package com.ibm.pross.common.util.serialization;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;

public class ClassSerialization {

	/**
	 * Serializes an object into a byte string using Java serialization
	 * 
	 * @param object
	 * @return
	 */
	public static byte[] serializeClass(final Serializable object) {
		try {
			final ByteArrayOutputStream bos = new ByteArrayOutputStream();
			final ObjectOutputStream oos = new ObjectOutputStream(bos);
			oos.writeObject(object);
			oos.flush();
			bos.flush();
			return bos.toByteArray();
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
	}

	/**
	 * Deserializes a previously serialized byte string into a java class
	 * 
	 * @param input
	 * @return
	 * @throws IOException 
	 * @throws ClassNotFoundException 
	 */
	public static Object deserializeClass(byte[] input) throws IOException, ClassNotFoundException {
			final ByteArrayInputStream bis = new ByteArrayInputStream(input);
			final ObjectInputStream ois = new ObjectInputStream(bis);
			return ois.readObject();
	}

}
