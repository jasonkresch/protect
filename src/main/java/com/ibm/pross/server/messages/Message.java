/*
 * Copyright (c) IBM Corporation 2018. All Rights Reserved.
 * Project name: pross
 * This project is licensed under the MIT License, see LICENSE.
 */

package com.ibm.pross.server.messages;

import java.io.Serializable;

public interface Message extends Serializable {

	/**
	 * Returns the index of the shareholder who purportedly sent this message.
	 * 
	 * @return
	 */
	int getSenderIndex();

	/**
	 * Determines whether the provided shareholder's index indicates the shareholder is a recipient 
	 * @param index
	 *            The index of the shareholder
	 * @return Returns true if the provided shareholder index is a recipient of
	 *         the message
	 */
	boolean isRecipient(int index);

}
