package com.ibm.pross.server.communication.handlers;

import com.ibm.pross.server.messages.Message;

public interface MessageHandler {

	public void handleMessage(final Message message);
	
}
