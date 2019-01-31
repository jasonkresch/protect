package com.ibm.pross.server.p2p.keymanager;

import com.ibm.pross.server.p2p.messages.Message;

public class PublicKeyManager {

	// For each participant, track initial and all later public keys. Mark the message IDs up until which they are valid.
	// Only consider them for the time periods (message ID) in which they are valid.
	// When someone's public key changes, update this.
	
	// Map of Participants to a TreeMap of Key Validity Ranges
	// Efficiently return the ValidityRange Object
	
	// Also need to ensure we sign with old keys, if we ever need to resend those old ones??
	// Archive all delivered messages. Anyone who had the old set of keys ought to be able to catch up.
	
	public boolean isMessageValid(final Message message)
	{
		// Check message signature
		
		// Check message ID within min and max
		return false;
	}
	
}
