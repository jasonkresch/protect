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

import com.ibm.pross.common.util.serialization.HexUtil;
import com.ibm.pross.server.channel.ChannelListener;

import bftsmart.tom.MessageContext;
import bftsmart.tom.ServiceReplica;
import bftsmart.tom.server.defaultservices.DefaultSingleRecoverable;

/**
 * Example replica that implements a BFT replicated service.
 * 
 * @author jresch
 */

public class BftListenerWrapper extends DefaultSingleRecoverable {

	private final ChannelListener listener;

	public BftListenerWrapper(final ChannelListener listener) {
		this.listener = listener;
		new ServiceReplica(listener.getId(), this, this);
	}

	@Override
	public byte[] appExecuteUnordered(final byte[] command, final MessageContext msgCtx) {
		//System.out.println("Received message: " + HexUtil.binToHex(command));
		this.listener.receiveSerializedMessage(command);
		return command;
	}

	@Override
	public byte[] appExecuteOrdered(byte[] command, MessageContext msgCtx) {
		//System.out.println("Received message: " + HexUtil.binToHex(command));
		this.listener.receiveSerializedMessage(command);
		return command;
	}
	
    @Override
    public void installSnapshot(byte[] state) {
        // Not yet implemented
    }

    @Override
    public byte[] getSnapshot() {
    	// Not yet implemented
        return new byte[0];
    }
}
