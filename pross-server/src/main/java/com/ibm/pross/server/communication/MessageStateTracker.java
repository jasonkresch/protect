package com.ibm.pross.server.communication;

import java.io.Serializable;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.ConcurrentSkipListSet;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import com.ibm.pross.server.messages.SignedMessage;

/**
 * Tracks every SignedMessage that has been seen and maps it to a set of who we
 * is unconfirmed to have seen the message. We know someone has seen a message
 * if we receive it from them, or if they acknowledge it from us while we
 * stubbornly send a message to them. We can stop stubbornly sending once we
 * know they have seen it.
 */
public class MessageStateTracker implements Serializable {

	private static final long serialVersionUID = -6169815397029123567L;

	// Map of every seen message to a set of unconfirmed witnesses to that message
	private final ConcurrentMap<SignedMessage, Set<Integer>> knownMessages = new ConcurrentHashMap<>();

	private final int numEntites;
	private final int myIndex;

	/**
	 * Constructs a message state tracker given a total number of servers and our
	 * own index
	 * 
	 * @param numEntities
	 *            The total number of relaying servers in the system
	 * @param myIndex
	 *            Our own index
	 */
	public MessageStateTracker(final int numEntities, final int myIndex) {
		this.numEntites = numEntities;
		this.myIndex = myIndex;
	}

	/**
	 * Records a message received from the given (already validated) sender. If this
	 * is a brand new message that has not previously been seen this method returns
	 * true, otherwise if this message has been seen before (regardless of sender)
	 * returns false.
	 * 
	 * @param senderId
	 *            The authenticated sender of this message (not necessarily the
	 *            originator but who relayed it to us).
	 * 
	 * @param acknowledgement
	 *            Set to true when this message is sent as an acknowledgement of a
	 *            message received from this party (relayed or not), false if this
	 *            is being sent.
	 * 
	 * @param signedMessage
	 *            The content of the relayed message, which itself is signed by the
	 *            originator. It is required that this signature has already been
	 *            checked.
	 * 
	 * @return True if this message has never before been seen. This can be used to
	 *         trigger relayed broadcasts.
	 */
	public synchronized boolean recordMessage(final int senderId, final SignedMessage signedMessage) {

		// Ensure the sender id is within allowed range
		if (senderId < 1 || senderId > this.numEntites) {
			throw new IllegalArgumentException("Sender ID is in invalid range. Was: " + senderId);
		}

		// Attempt to insert a new set containing everyone
		final List<Integer> everyone = IntStream.rangeClosed(1, this.numEntites).boxed().collect(Collectors.toList());
		final Set<Integer> newUnconfirmedSet = new ConcurrentSkipListSet<>(everyone);
		final Set<Integer> existingUnconfirmedSet = this.knownMessages.putIfAbsent(signedMessage, newUnconfirmedSet);
		final boolean isNewlySeenMessage = (existingUnconfirmedSet == null);

		// Remove the sender from the unconfirmed set (they are a witness of this
		// message)
		final Set<Integer> setToUse = isNewlySeenMessage ? newUnconfirmedSet : existingUnconfirmedSet;
		setToUse.remove(senderId);

		// Remove ourselves from unconfirmed (we just saw the message)
		setToUse.remove(this.myIndex);

		return isNewlySeenMessage;
	}

	/**
	 * Returns a map keyed by messages which have not been seen by everyone. Each
	 * message is mapped to a set of entity ids of those entities who we have not
	 * been confirmed as witnesses of the message
	 */
	public synchronized Map<SignedMessage, Set<Integer>> determineMessagesNotKnownByAll() {

		// Form map of messages not known to all
		final Map<SignedMessage, Set<Integer>> messagesNotKnownByAll = new ConcurrentHashMap<>();
		for (final Entry<SignedMessage, Set<Integer>> entry : this.knownMessages.entrySet()) {
			final Set<Integer> unconfirmedSet = entry.getValue();

			// Check if there are any unconfirmed witnesses
			if (!unconfirmedSet.isEmpty()) {
				// Remove witnesses from the complete set, leaving entities yet to see it
				messagesNotKnownByAll.put(entry.getKey(), unconfirmedSet);
			}
		}

		return messagesNotKnownByAll;
	}

	/**
	 * Returns a set of unconfirmed witnesses to the given signed message
	 * 
	 * @param signedMessage
	 * @return
	 */
	public synchronized Set<Integer> determineUnconfirmedWitnesses(final SignedMessage signedMessage) {
		return this.knownMessages.get(signedMessage);
	}

}
