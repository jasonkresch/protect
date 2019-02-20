/**
Copyright (c) 2007-2013 Alysson Bessani, Eduardo Alchieri, Paulo Sousa, and the authors indicated in the @author tags

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package com.ibm.pross.server.channel.bft;

import java.io.IOException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;

import com.ibm.pross.server.channel.ChannelListener;

import bftsmart.tom.MessageContext;
import bftsmart.tom.ServiceReplica;
import bftsmart.tom.server.FIFOExecutable;
import bftsmart.tom.server.defaultservices.DefaultSingleRecoverable;

/**
 * Example replica that implements a BFT replicated service.
 * 
 * @author jresch
 */

public class BftListenerWrapper extends DefaultSingleRecoverable implements FIFOExecutable {

	private final ChannelListener listener;
	private volatile ServiceReplica serviceReplica;

	public BftListenerWrapper(final ChannelListener listener) {
		this.listener = listener;

		// Start service replica in a thread
		final Thread thread = new Thread() {
			public void run() {
				BftListenerWrapper.this.serviceReplica = new ServiceReplica(listener.getId(), BftListenerWrapper.this,
						BftListenerWrapper.this);
			}
		};
		thread.start();
	}

	public boolean isReady() {
		return ((this.serviceReplica != null) && (this.serviceReplica.isServiceReady()));
	}

	@Override
	public byte[] appExecuteUnordered(final byte[] command, final MessageContext msgCtx) {
		throw new RuntimeException("Unused method was invoked!");
	}

	@Override
	public byte[] appExecuteOrdered(byte[] command, MessageContext msgCtx) {
		throw new RuntimeException("Unused method was invoked!");
	}

	@Override
	public byte[] executeUnorderedFIFO(byte[] command, MessageContext msgCtx, int clientId, int operationId) {
		throw new RuntimeException("Unused method was invoked!");
	}

	@Override
	public byte[] executeOrderedFIFO(byte[] command, MessageContext msgCtx, int clientId, int operationId) {
		try {
			this.listener.receiveSerializedMessage(command);
		} catch (ClassNotFoundException | BadPaddingException | IllegalBlockSizeException | IOException e) {
			e.printStackTrace();
			return null;
		}
		return command;
	}

	@Override
	public void installSnapshot(byte[] state) {
		throw new RuntimeException("Not yet implemented!");
	}

	@Override
	public byte[] getSnapshot() {
		// Not yet implemented
		return new byte[0];
	}

}
