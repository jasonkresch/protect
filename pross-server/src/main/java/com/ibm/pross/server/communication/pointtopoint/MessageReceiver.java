package com.ibm.pross.server.communication.pointtopoint;

import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.Semaphore;
import java.util.concurrent.atomic.AtomicBoolean;

public class MessageReceiver {

	// Constants
	public static long MAX_MESSAGE_SIZE = 1_000_000; // 1 MB;
	static final int TIMEOUT = 30_000; // 30 seconds;
	static final int NUM_PROCESSING_THREADS = 10;
	static final int MESSAGE_QUEUE_CAPACITY = 100;
	static final boolean DEBUG_MODE = false;

	// Member fields
	private final int localPort;
	private final AtomicBoolean started = new AtomicBoolean(false);
	private final BlockingQueue<byte[]> messageQueue = new LinkedBlockingQueue<>(MESSAGE_QUEUE_CAPACITY);
	
	// Variables created upon start
	private volatile ServerSocket listeningSocket;
	private volatile ListeningThread listeningThread;
	private volatile ExecutorService threadPool;
	private volatile Semaphore permits;

	public MessageReceiver(final int localPort) {
		this.localPort = localPort;
	}

	public byte[] awaitNextMessage() {
		try {
			return this.messageQueue.take();
		} catch (InterruptedException e) {
			throw new RuntimeException(e);
		}
	}

	public void start() throws IOException {
		// Only start if we were stopped
		if (this.started.compareAndSet(false, true)) {

			// Setup accept permits
			this.permits = new Semaphore(NUM_PROCESSING_THREADS * 2);
			
			// Start listening
			this.listeningSocket = new ServerSocket(this.localPort);

			// Start thread pool
			this.threadPool = Executors.newFixedThreadPool(NUM_PROCESSING_THREADS);

			// Start listen thread
			this.listeningThread = new ListeningThread();
			this.listeningThread.start();
		}
	}

	public void stop() throws IOException {
		// Only stop if we were started
		if (this.started.compareAndSet(true, false)) {

			// Stop listening socket
			this.listeningSocket.close();

			// Interrupted thread
			this.listeningThread.interrupt();

			// Stop listen thread
			try {
				this.listeningThread.join();
			} catch (InterruptedException e) {
				// Ignored
			}
			// Shutdown executor
			this.threadPool.shutdown();
		}
	}

	public class ListeningThread extends Thread {
		public void run() {
			while (started.get()) {

				// Wait for a permit before accepting connection
				try {
					permits.acquire();
				} catch (InterruptedException e) {
					// Interrupted
					return;
				}

				try {
					// Await connection
					final Socket connectionSocket = listeningSocket.accept();
					connectionSocket.setSoTimeout(TIMEOUT);
					connectionSocket.setTcpNoDelay(true);

					printDebug("Accepted connection from: " + connectionSocket.toString());

					// Hand off socket to thread pool
					threadPool.submit(new MessageProcessingTask(connectionSocket));
				} catch (IOException e) {
					/* Ignored */}
			}
		}
	}

	public class MessageProcessingTask implements Callable<Void> {

		private final Socket connectionSocket;

		public MessageProcessingTask(final Socket connectionSocket) {
			this.connectionSocket = connectionSocket;
		}

		@Override
		public Void call() throws Exception {

			try {
				// Setup input and output streams
				final DataInputStream inFromClient = new DataInputStream(connectionSocket.getInputStream());
				final DataOutputStream outToClient = new DataOutputStream(connectionSocket.getOutputStream());

				final ByteArrayOutputStream receivedData;

				// Get message from client
				final int messageSize = inFromClient.readInt();
				printDebug("Waiting for: " + messageSize + " more bytes");
				if (messageSize > MAX_MESSAGE_SIZE) {
					// Send response
					outToClient.writeBytes("Invalid length. Max is " + MAX_MESSAGE_SIZE + " bytes\n");
				} else {
					receivedData = new ByteArrayOutputStream(messageSize);
					byte[] messageBuffer = new byte[messageSize];
					int bytesReceived = 0;

					try {
						do {
							final int received = inFromClient.read(messageBuffer);
							if (received == -1) {
								break; // EOF
							}
							receivedData.write(messageBuffer, 0, received);
							bytesReceived += received;
							printDebug("Received " + bytesReceived + " bytes");
						} while (bytesReceived < messageSize);
					} catch (IOException e) {
						printDebug("Exception on socket: " + connectionSocket + " " + e.getMessage());
					}

					if (bytesReceived == messageSize) {
						printDebug("Received complete message: " + new String(receivedData.toByteArray()));
						messageQueue.put(receivedData.toByteArray());
					} else {
						printDebug("Received partial message: " + new String(receivedData.toByteArray()));
					}

					outToClient.writeBytes("Message received\n");
				}

				outToClient.flush();
				outToClient.close();
			} finally {
				// Allow new connections to be accepted
				permits.release();
			}

			printDebug("Finished connection with: " + connectionSocket);
			return null;
		}
	}

	private void printDebug(final String message) {
		if (DEBUG_MODE) {
			System.out.println(message);
		}
	}

	public static void main(final String[] args) throws IOException, InterruptedException {
		final MessageReceiver receiver = new MessageReceiver(6798);
		receiver.start();

		for (int i = 0; i < 3; i++) {
			byte[] message = receiver.awaitNextMessage();
			System.out.println("READY TO PROCESS: " + new String(message));
		}

		receiver.stop();

		receiver.start();

		for (int i = 0; i < 3; i++) {
			byte[] message = receiver.awaitNextMessage();
			System.out.println("READY TO PROCESS, Take 2: " + new String(message));
		}

		receiver.stop();
	}
}
