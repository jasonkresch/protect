package com.ibm.pross.server.util;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.SyncFailedException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.util.UUID;

import com.ibm.pross.server.messages.SignedMessage;

public class AtomicFileOperations {

	public static void atomicWriteSignedMessage(final File destinationFile, final SignedMessage signedMessage)
			throws SyncFailedException, IOException {
		byte[] messageData = MessageSerializer.serializeSignedMessage(signedMessage);
		atomicWriteBytes(destinationFile, messageData);
	}
	
	public static void atomicWriteString(final File destinationFile, final String string)
			throws SyncFailedException, IOException {
		atomicWriteBytes(destinationFile, string.getBytes(StandardCharsets.UTF_8));
	}
	
	public static void atomicWriteBytes(final File destinationFile, final byte[] data)
			throws SyncFailedException, IOException {

		// Create a temporary file in the same directory as the desination file
		final File parentDirectory = destinationFile.getParentFile();
		parentDirectory.mkdirs();
		final File tempFile = new File(parentDirectory,
				destinationFile.getName() + UUID.randomUUID().toString() + ".tmp");

		try (final FileOutputStream fos = new FileOutputStream(tempFile);) {

			// FIXME: Make serialization of state objects more efficient, currently a
			// performance problem

			// Do everything we can to ensure a flush to storage
			fos.write(data);
			//fos.getChannel().force(true);
			fos.flush();
			//fos.getFD().sync();
			fos.close();

			try {
				// Attempt atomic rename
				Files.move(Paths.get(tempFile.getAbsolutePath()), Paths.get(destinationFile.getAbsolutePath()),
						StandardCopyOption.ATOMIC_MOVE);
			} catch (IOException e) {
				// Fall back to normal rename (may not be atomic)
				System.err.println("Atomic moves not supported on this platform. This can lead to data loss!");
				tempFile.renameTo(destinationFile);
			}
		}
	}

	/**
	 * Attempts to read a previously written object from local storage.
	 * 
	 * @param saveFile
	 * @return
	 */
	public static SignedMessage readSignedMessage(final File saveFile) throws IOException {
		
		// Read serialized object
		byte[] messageData = Files.readAllBytes(saveFile.toPath());
		
		// Deserialize message
		return MessageSerializer.deserializeSignedMessage(messageData);
	}

}
