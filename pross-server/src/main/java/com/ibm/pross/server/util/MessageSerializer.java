package com.ibm.pross.server.util;

import com.ibm.pross.server.messages.Payload;
import com.ibm.pross.server.messages.Message;
import com.ibm.pross.server.messages.RelayedMessage;
import com.ibm.pross.server.messages.SignedMessage;
import com.ibm.pross.server.messages.SignedRelayedMessage;

import io.protostuff.LinkedBuffer;
import io.protostuff.ProtostuffIOUtil;
import io.protostuff.Schema;
import io.protostuff.runtime.RuntimeSchema;

public class MessageSerializer {

	// Schemas for message serialization
	public static final Schema<SignedRelayedMessage> SIGNED_RELAYED_MESSAGE_SCHEMA = RuntimeSchema
			.getSchema(SignedRelayedMessage.class);
	public static final Schema<RelayedMessage> RELAYED_MESSAGE_SCHEMA = RuntimeSchema.getSchema(RelayedMessage.class);

	public static final Schema<SignedMessage> SIGNED_MESSAGE_SCHEMA = RuntimeSchema.getSchema(SignedMessage.class);
	public static final Schema<Message> MESSAGE_SCHEMA = RuntimeSchema.getSchema(Message.class);
	public static final Schema<Payload> PAYLOAD_SCHEMA = RuntimeSchema.getSchema(Payload.class);

	public static final int MAX_MESSAGE_SIZE = 256 * 1024; // 256 KB

	/**
	 * Serializes an SignedRelayedMessage into a byte string using Java
	 * serialization
	 * 
	 * @param object
	 * @return
	 */
	public static byte[] serializeSignedRelayedMessage(final SignedRelayedMessage signedRelayedMessage) {

		// Re-use (manage) this buffer to avoid allocating on every serialization
		final LinkedBuffer buffer = LinkedBuffer.allocate(MAX_MESSAGE_SIZE);

		try {
			// Perform serialization
			return ProtostuffIOUtil.toByteArray(signedRelayedMessage, SIGNED_RELAYED_MESSAGE_SCHEMA, buffer);
		} finally {
			// Release buffer
			buffer.clear();
		}

	}

	/**
	 * Deserializes a previously serialized byte array into a signed relayed message
	 * 
	 * @param input
	 * @return
	 */
	public static SignedRelayedMessage deserializeSignedRelayedMessage(byte[] serializedSignedRelayedMessage) {
		final SignedRelayedMessage parsedSignedRelayedMessage = SIGNED_RELAYED_MESSAGE_SCHEMA.newMessage();
		ProtostuffIOUtil.mergeFrom(serializedSignedRelayedMessage, parsedSignedRelayedMessage,
				SIGNED_RELAYED_MESSAGE_SCHEMA);
		return parsedSignedRelayedMessage;
	}

	/**
	 * Serializes an RelayedMessage into a byte string using Java serialization
	 * 
	 * @param object
	 * @return
	 */
	public static byte[] serializeRelayedMessage(final RelayedMessage relayedMessage) {

		// Re-use (manage) this buffer to avoid allocating on every serialization
		final LinkedBuffer buffer = LinkedBuffer.allocate(MAX_MESSAGE_SIZE);

		try {
			// Perform serialization
			return ProtostuffIOUtil.toByteArray(relayedMessage, RELAYED_MESSAGE_SCHEMA, buffer);
		} finally {
			// Release buffer
			buffer.clear();
		}

	}

	/**
	 * Deserializes a previously serialized byte array into a relayed message
	 * 
	 * @param input
	 * @return
	 */
	public static RelayedMessage deserializeRelayedMessage(byte[] serializedRelayedMessage) {
		final RelayedMessage parsedRelayedMessage = RELAYED_MESSAGE_SCHEMA.newMessage();
		ProtostuffIOUtil.mergeFrom(serializedRelayedMessage, parsedRelayedMessage, RELAYED_MESSAGE_SCHEMA);
		return parsedRelayedMessage;
	}

	/**
	 * Serializes an Relayed Message into a byte string using Java serialization
	 * 
	 * @param object
	 * @return
	 */
	public static byte[] serializeSignedMessage(final SignedMessage signedMessage) {

		// Re-use (manage) this buffer to avoid allocating on every serialization
		final LinkedBuffer buffer = LinkedBuffer.allocate(MAX_MESSAGE_SIZE);

		try {
			// Perform serialization
			return ProtostuffIOUtil.toByteArray(signedMessage, SIGNED_MESSAGE_SCHEMA, buffer);
		} finally {
			// Release buffer
			buffer.clear();
		}

	}

	/**
	 * Deserializes a previously serialized byte array into a signed message
	 * 
	 * @param input
	 * @return
	 */
	public static SignedMessage deserializeSignedMessage(byte[] serializedSignedMessage) {
		final SignedMessage parsedSignedMessage = SIGNED_MESSAGE_SCHEMA.newMessage();
		ProtostuffIOUtil.mergeFrom(serializedSignedMessage, parsedSignedMessage, SIGNED_MESSAGE_SCHEMA);
		return parsedSignedMessage;
	}

	/**
	 * Serializes a Message into a byte string using Java serialization
	 * 
	 * @param object
	 * @return
	 */
	public static byte[] serializeMessage(final Message message) {

		// Re-use (manage) this buffer to avoid allocating on every serialization
		final LinkedBuffer buffer = LinkedBuffer.allocate(MAX_MESSAGE_SIZE);

		try {
			// Perform serialization
			return ProtostuffIOUtil.toByteArray(message, MESSAGE_SCHEMA, buffer);
		} finally {
			// Release buffer
			buffer.clear();
		}

	}

	/**
	 * Deserializes a previously serialized byte array into a message
	 * 
	 * @param input
	 * @return
	 */
	public static Message deserializeMessage(byte[] serializedMessage) {
		final Message parsedMessage = MESSAGE_SCHEMA.newMessage();
		ProtostuffIOUtil.mergeFrom(serializedMessage, parsedMessage, MESSAGE_SCHEMA);
		return parsedMessage;
	}

	/**
	 * Serializes a Payload into a byte array using Java serialization
	 * 
	 * @param object
	 * @return
	 */
	public static byte[] serializePayload(final Payload payload) {

		// Re-use (manage) this buffer to avoid allocating on every serialization
		final LinkedBuffer buffer = LinkedBuffer.allocate(MAX_MESSAGE_SIZE);

		try {
			// Perform serialization
			return ProtostuffIOUtil.toByteArray(payload, PAYLOAD_SCHEMA, buffer);
		} finally {
			// Release buffer
			buffer.clear();
		}

	}

	/**
	 * Deserializes a previously serialized byte array into a payload
	 * 
	 * @param input
	 * @return
	 */
	public static Payload deserializePayload(byte[] serializedPayload) {
		final Payload parsedPayload = PAYLOAD_SCHEMA.newMessage();
		ProtostuffIOUtil.mergeFrom(serializedPayload, parsedPayload, PAYLOAD_SCHEMA);
		return parsedPayload;
	}

}
