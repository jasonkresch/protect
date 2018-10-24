package com.ibm.pross.server.dkgnew;

import java.util.AbstractMap.SimpleEntry;
import java.util.Collections;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class AlertLog {

	// Enumeration of possible error conditions
	public static enum ErrorCondition {
		DuplicateMessage,
		InconsistentShare,
		InvalidShareContribution,
		InvalidVerificationVector,
		BadRebuttal,
		StateViolation,
		InvalidProof,
		InvalidBulkProof,
		UnrecognizedMessageType,
		InvalidCiphertext;
	}

	// Log of errors
	private final Map<SimpleEntry<Integer, Integer>, ErrorCondition> alerts = new ConcurrentHashMap<>();

	public void reportError(final int reporterIndex, final int reportedIndex, final ErrorCondition error) {

		// Add error report to error log
		alerts.put(new SimpleEntry<Integer, Integer>(reporterIndex, reportedIndex), error);

	}

	public Map<SimpleEntry<Integer, Integer>, ErrorCondition> getAlerts() {
		return Collections.unmodifiableMap(alerts);
	}

	

}
