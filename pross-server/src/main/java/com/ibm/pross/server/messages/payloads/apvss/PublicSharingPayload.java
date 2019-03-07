package com.ibm.pross.server.messages.payloads.apvss;

import com.ibm.pross.common.util.pvss.PublicSharing;
import com.ibm.pross.server.messages.Payload;

public class PublicSharingPayload extends Payload {

	public PublicSharingPayload(final PublicSharing publicSharing) {
		super(OpCode.PS, publicSharing);
	}

	public PublicSharing getPublicSharing() {
		return (PublicSharing) super.getData();
	}

	@Override
	public String toString() {
		return "PublicSharingPayload [publicSharing=" + getPublicSharing() + "]";
	}

}