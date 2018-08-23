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

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Random;

import bftsmart.tom.ServiceProxy;
import bftsmart.tom.util.Logger;

/**
 * Example client that updates a BFT replicated service (a counter).
 * 
 * @author alysson
 */
public class LoggerClient {

	public static String generateString(int length)
	{
		final Random rand = new Random();
		final StringBuffer buffer = new StringBuffer();
		
		for (int i = 0; i < length; i++)
		{
			final int r = rand.nextInt(26) + 65;
			buffer.append(Character.toString ((char) r));
		}
		return buffer.toString();
	}

	public static void main(String[] args) throws IOException {
		if (args.length < 2) {
			System.out.println("Usage: java ... CounterClient <process id> <increment> [<number of operations>]");
			System.out.println("       if <increment> equals 0 the request will be read-only");
			System.out.println("       default <number of operations> equals 1000");
			System.exit(-1);
		}

		ServiceProxy counterProxy = new ServiceProxy(Integer.parseInt(args[0]));

		Logger.debug = false;

		try {

			int strLen = Integer.parseInt(args[1]);
			int numberOfOps = (args.length > 2) ? Integer.parseInt(args[2]) : 1000;

			for (int i = 0; i < numberOfOps; i++) {

				String msg = generateString(strLen);
				
				System.out.print("Invocation " + i + ", message = " + msg);
				byte[] reply = counterProxy.invokeOrdered(msg.getBytes(StandardCharsets.UTF_8)); // magic happens here

				if (reply != null) {
					String newValue = new String(reply, StandardCharsets.UTF_8);
					System.out.println(", returned value: " + newValue);
				} else {
					System.out.println(", ERROR! Exiting.");
					break;
				}
			}
		} catch (NumberFormatException e) {
			counterProxy.close();
		}
	}
}
