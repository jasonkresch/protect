package com.ibm.pross.server.communication.pointtopoint;

import java.io.DataOutputStream;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketAddress;

/**
 * Equivalent to a "FairLossLink". Will attempt to deliver a message with a non-zero probability of success over TCP/IP.
 */
public class MessageSender {

	static final int TIMEOUT = 30_000; // 30 seconds;

	private final String remoteHost;
	private final int remotePort;

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
		final Thread sendThread = new Thread() {
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
		};

		sendThread.start();
	}

}
