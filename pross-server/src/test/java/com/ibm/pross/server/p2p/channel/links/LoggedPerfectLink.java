package com.ibm.pross.server.p2p.channel.links;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.UUID;

import com.ibm.pross.server.p2p.messages.Message;
import com.ibm.pross.server.p2p.messages.MessagePayload;

public class LoggedPerfectLink extends StubbornLink {

	public static String PERSIST_FILE_PREFIX = "RECEIVED-MSGS-";

	private final List<Message> deliveredMessages;
	private final File saveLocation;

	public LoggedPerfectLink(final int senderIdentifier) {
		super();
		this.saveLocation = new File(PERSIST_FILE_PREFIX + senderIdentifier);
		this.deliveredMessages = Collections.synchronizedList(loadState());
		
		if (this.deliveredMessages.size() > 0)
		{
			notifyApplicationOfUpdates();
		}
	}

	/**
	 * Attempts to load state from a save file. If not found, returns an empty list.
	 * 
	 * @return
	 */
	@SuppressWarnings("unchecked")
	private final List<Message> loadState() {
		// Attempt to read a previous state from the save file
		try (final FileInputStream fis = new FileInputStream(this.saveLocation);
				final ObjectInputStream ois = new ObjectInputStream(fis);) {
			final Object object = ois.readObject();
			if (object instanceof List) {
				return (List<Message>) object;
			}
		} catch (IOException | ClassNotFoundException | ClassCastException e) {
			// Ignore, we will return an empty list
		}

		return new LinkedList<Message>();
	}

	@Override
	public void deliver(final Message message) {
		// Ensure no duplicate messages are delivered
		synchronized (this.deliveredMessages) {
			if (!this.deliveredMessages.contains(message)) {
				this.deliveredMessages.add(message);
				this.deliverOnce(message);
			}
		}
	}

	private void deliverOnce(final Message message) {
		// Persist delivered messages to storage and sync
		try {
			saveState();
		} catch (IOException e) {
			System.out.println("FATAL ERROR, failed to save state");
			System.exit(-1);
		}

		notifyApplicationOfUpdates();
	}

	private final void saveState() throws IOException {
		final File tempFile = File.createTempFile(PERSIST_FILE_PREFIX, UUID.randomUUID().toString());

		// Attempt to read a previous state from the save file
		try (final FileOutputStream fos = new FileOutputStream(tempFile);
				final ObjectOutputStream ois = new ObjectOutputStream(fos);) {
			ois.writeObject(this.deliveredMessages);
			ois.flush();
			fos.getFD().sync();
			tempFile.renameTo(this.saveLocation);
			Files.move(Paths.get(tempFile.getAbsolutePath()), Paths.get(this.saveLocation.getAbsolutePath()), StandardCopyOption.ATOMIC_MOVE);
		}
		
		// TODO: Store a hash too so we can validate consistency
		// TODO: Use an append mode
	}

	// TODO: Make a logged stubborn send (keep local log of all messages being stubbornly sent), add to it on recovery
	
	public synchronized void notifyApplicationOfUpdates() {
		// Signals application that there are new messages in getDelivered()
		// High level application should keep track of the id of the last message it processed
		final int latest = getDelivered().size() - 1;
		final Message message = getDelivered().get(latest);
		System.out.println("Received logged unique message: " + message);
	}

	public List<Message> getDelivered() {
		return Collections.unmodifiableList(this.deliveredMessages);
	}

	public static void main(final String args[]) throws Exception {

		final int senderId = 3000;
		final LoggedPerfectLink link = new LoggedPerfectLink(senderId);

		final Message msg1 = new Message(senderId, 456, 1, new MessagePayload("hello"), null);
		link.repeatSendAttempt(msg1);

		final Message msg2 = new Message(senderId, 456, 2, new MessagePayload("hi"), null);
		link.repeatSendAttempt(msg2);

		final Message msg3 = new Message(senderId, 678, 3, new MessagePayload("hey"), null);
		link.repeatSendAttempt(msg3);

		// Stay alive
		Thread.sleep(RESEND_DELAY * 2);

		final Message msg4 = new Message(senderId, 678, 4, new MessagePayload("good morning"), null);
		link.repeatSendAttempt(msg4);

		final Message msg5 = new Message(senderId, 678, 5, new MessagePayload("good evening"), null);
		link.repeatSendAttempt(msg5);

		// Stay alive
		Thread.sleep(RESEND_DELAY * 5);

	}
}
