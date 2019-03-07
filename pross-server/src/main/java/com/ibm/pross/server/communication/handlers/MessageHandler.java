package com.ibm.pross.server.communication.handlers;

import com.ibm.pross.server.messages.PublicMessage;

public interface MessageHandler {

	public void handleMessage(final PublicMessage message);
	
}
