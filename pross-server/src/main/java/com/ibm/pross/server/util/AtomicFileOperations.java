package com.ibm.pross.server.util;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.io.SyncFailedException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.util.UUID;

public class AtomicFileOperations {

	public static void atomicWrite(final File destinationFile, final Serializable object)
			throws SyncFailedException, IOException {

		// Create a temporary file in the same directory as the desination file
		final File parentDirectory = destinationFile.getParentFile();
		parentDirectory.mkdirs();
		final File tempFile = new File(parentDirectory,
				destinationFile.getName() + UUID.randomUUID().toString() + ".tmp");

		try (final FileOutputStream fos = new FileOutputStream(tempFile);
				final ObjectOutputStream ois = new ObjectOutputStream(fos);) {

			// Do everything we can to ensure a flush to storage
			ois.writeObject(object);
			fos.getChannel().force(true);
			ois.flush();
			fos.flush();
			fos.getFD().sync();
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
	public static Object readObject(final File saveFile) throws IOException {
		// Attempt to read a previous state from the save file
		try (final FileInputStream fis = new FileInputStream(saveFile);
				final ObjectInputStream ois = new ObjectInputStream(fis);) {
			return ois.readObject();
		} catch (IOException | ClassNotFoundException | ClassCastException e) {
			throw new IOException("Failed to load object", e);
		}

	}

}
