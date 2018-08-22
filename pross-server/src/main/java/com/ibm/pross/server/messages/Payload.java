/*
 * Copyright (c) IBM Corporation 2018. All Rights Reserved.
 * Project name: pross
 * This project is licensed under the MIT License, see LICENSE.
 */

package com.ibm.pross.server.messages;

import java.io.Serializable;

public interface Payload extends Serializable {

	public enum OpCode {

		NA, // NA (e.g., for private paylods)

		/***** Distributed Key Generation *****/

		// DKG: Initial establishment of the secret (x)
		DKG_VSS, // Distributed key generation init
		DKG_ACCUSATIONS, // Accusations
		DKG_REBUTTAL, // Rebuttals

		/***** Proactive Secret Sharing *****/

		// PROSS: Refresh operation
		REFRESH_VSS, // Verifiable SS
		REFRESH_ACCUSATIONS, // Accusations
		REFRESH_REBUTTAL, // Rebuttals

		// PROSS: Reconstruction operation
		RECONSTRUCTION_DETECT_CORRUPT, // Detection
		RECONSTRUCTION_VSS, // Reconstruction VSS
		RECONSTRUCTION_ACCUSATIONS, // Accusations
		RECONSTRUCTION_REBUTTAL, // Rebuttals
		RECONSTRUCTION_CONTRIBUTION, // Contribution

		// PROSS: Dynamic rekey operation
		DYNAMIC_REKEY; // New public keys

	}

	public OpCode getOpcode();

}
