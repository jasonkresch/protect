/*
 * Copyright (c) IBM Corporation 2018. All Rights Reserved.
 * Project name: pross
 * This project is licensed under the MIT License, see LICENSE.
 */

package com.ibm.pross.server;

public class Clock {

	private volatile long currentTime = 0;
	
	public long getTime()
	{
		return currentTime;
	}
	
	public void advanceTime()
	{
		currentTime = currentTime + 1;
	}
}
