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
package bftsmart.demo.logger;

import java.nio.charset.StandardCharsets;

import bftsmart.tom.MessageContext;
import bftsmart.tom.ServiceReplica;
import bftsmart.tom.server.defaultservices.DefaultSingleRecoverable;

/**
 * Example replica that implements a BFT replicated service (a counter). If the
 * increment > 0 the counter is incremented, otherwise, the counter value is
 * read.
 * 
 * @author alysson
 */

public final class LoggerServer extends DefaultSingleRecoverable {

	private String message = "";
	private int iterations = 0;

	public LoggerServer(int id) {
		new ServiceReplica(id, this, this);
	}

	@Override
	public byte[] appExecuteUnordered(byte[] command, MessageContext msgCtx) {
		iterations++;

		System.out.println("(" + iterations + ") Counter message value: " + this.message);
		return this.message.getBytes(StandardCharsets.UTF_8);
	}

	@Override
	public byte[] appExecuteOrdered(byte[] command, MessageContext msgCtx) {
		iterations++;

		String message = new String(command, StandardCharsets.UTF_8);

		System.out.println("(" + iterations + ") Message was added. Current value = " + message);

		this.message = message;

		return message.getBytes(StandardCharsets.UTF_8);

	}

	public static void main(String[] args) {
		if (args.length < 1) {
			System.out.println("Use: java CounterServer <processId>");
			System.exit(-1);
		}
		new LoggerServer(Integer.parseInt(args[0]));
	}

	@Override
	public void installSnapshot(byte[] state) {
		System.out.println("setState called");
		this.message = new String(state, StandardCharsets.UTF_8);
	}

	@Override
	public byte[] getSnapshot() {
		System.out.println("getState called");
		return this.message.getBytes(StandardCharsets.UTF_8);
	}
}
