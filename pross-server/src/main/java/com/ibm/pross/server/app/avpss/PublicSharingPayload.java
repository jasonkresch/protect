package com.ibm.pross.server.app.avpss;

import java.io.Serializable;

import com.ibm.pross.common.util.pvss.PublicSharing;
import com.ibm.pross.server.messages.Payload;

public class PublicSharingPayload extends Payload implements Serializable {

	private static final long serialVersionUID = -3305552097003223276L;

	private final PublicSharing publicSharing;

	public PublicSharingPayload(final PublicSharing publicSharing) {
		super(OpCode.PS, publicSharing);
		this.publicSharing = publicSharing;
	}

	public PublicSharing getPublicSharing() {
		return publicSharing;
	}

	@Override
	public String toString() {
		return "PublicSharingPayload [publicSharing=" + publicSharing + "]";
	}

}