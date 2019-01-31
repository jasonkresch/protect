package com.ibm.pross.server.communication.pointtopoint;

import java.io.DataOutputStream;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketAddress;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Equivalent to a "FairLossLink". Will attempt to deliver a message with a non-zero probability of success over TCP/IP.
 */
public class MessageSender {

	static final int TIMEOUT = 30_000; // 30 seconds;

	private final String remoteHost;
	private final int remotePort;

	public static ExecutorService FIXED_THREAD_POOL = Executors.newFixedThreadPool(10);
	
	public MessageSender(final String remoteHost, final int remotePort) {
		this.remoteHost = remoteHost;
		this.remotePort = remotePort;
	}

	/**
	 * Attempt to connect to the server to deliver the message content
	 * 
	 * @param messageContent
	 */
	public void attemptMessageDelivery(final byte[] message) {

		// Sending is done in a thread as it may timeout
		FIXED_THREAD_POOL.execute(new Runnable() {
			@Override
			public void run() {
				try {
					// Connect to server
					final Socket clientSocket = new Socket();
					clientSocket.setTcpNoDelay(true);
					clientSocket.setSoTimeout(TIMEOUT);

					final SocketAddress address = new InetSocketAddress(remoteHost, remotePort);
					clientSocket.connect(address, TIMEOUT);

					// Setup input and output streams
					final DataOutputStream outToServer = new DataOutputStream(clientSocket.getOutputStream());

					// Send message to server
					outToServer.writeInt(message.length);
					outToServer.write(message);
					outToServer.flush();

					// Disconnect
					clientSocket.close();
				} catch (IOException e) {
					// Ignored
				}
			}
		});
	}

}
