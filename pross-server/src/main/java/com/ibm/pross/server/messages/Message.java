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
	 * Returns the name of the channel for this message
	 * @return
	 */
	String getChannelName();

	/**
	 * Determines whether the provided channel name indicates the shareholder is a recipient  for this message
	 * 
	 * @param channelName
	 *            The channel name of the shareholder
	 * @return Returns true if the provided shareholder index is a recipient of
	 *         the message
	 */
	boolean isRecipient(String channelName);

}
