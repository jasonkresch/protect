package com.ibm.pross.server.configuration.permissions;

import java.util.Collections;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

public class ClientPermissions {

	/**
	 * List of recognized permissions. Each permission has a code which can be used
	 * to form a bitmask.
	 * 
	 * <pre>
	 * #   - generate:     The ability to execute a DKG using this name to establish a secret (if one does not already exist with this name)
	 * #   - store:        The ability for a client to directly store shares of a secret to this key name (if one does not already exist with this name)
	 * #   - read:         The ability to recover a secret from its shares (should only be used for secrets that can be stored)
	 * #   - info:         The ability to request information about this key, including the name, creation time, epoch, last-refresh time, prime field and group information (RSA/DH/EC)
	 * #   - delete:       The ability to destroy the shares associated with this key, resetting its state and allowing a new key of this name to be created or stored.
	 * #   - recover       The ability to initiate a share recovery for shares of this key after one the shares becomes lost or deleted.
	 * #   - disable:      The ability to temporarily disable client actions from being performed against the shares of this key (note: does not prevent delete/enable/info)
	 * #   - enable:       The ability to re-enable client actions from being performed against shares of this key
	 * #   - exponentiate: The ability to compute an exponentiation (scalar multiply for EC curves) on a client-supplied base point: base^secret
	 * #   - sign:         The ability to perform an signature operation on a client-supplied message: message^(secret=d) mod N.  Secrets of this form must be stored and be under RSA or BLS groups.
	 * </pre>
	 */
	public enum Permissions {
		GENERATE(1 << 0), 
		STORE(1 << 1), 
		READ(1 << 2), 
		INFO(1 << 3), 
		DELETE(1 << 4),
		RECOVER(1 << 5), 
		DISABLE(1 << 6),
		ENABLE(1 << 7),
		EXPONENTIATE(1 << 8),
		SIGN(1 << 9);

		private final int permissionCode;

		private Permissions(int permissionCode) {
			this.permissionCode = permissionCode;
		}

		public final int getCode() {
			return this.permissionCode;
		}
	}

	// Map of secret names to a mask of permissions
	private final ConcurrentMap<String, Integer> secretPermissions;

	/**
	 * Default constructor, no permissions
	 */
	public ClientPermissions() {
		this(Collections.emptyMap());
	}

	/**
	 * Create client permissions from an existing permission map
	 * 
	 * @param secretPermissions A map of secret names to a bit mask of permissions
	 */
	public ClientPermissions(final Map<String, Integer> secretPermissions) {
		this.secretPermissions = new ConcurrentHashMap<>(secretPermissions);
	}

	/**
	 * Adds the given permission to the ser of client permissions
	 * 
	 * @param secretName
	 * @param permission
	 */
	public void addPermission(final String secretName, final Permissions permission) {
		synchronized (this.secretPermissions) {
			// Create mask with single value for this permission (if not already set)
			final Integer previous = this.secretPermissions.putIfAbsent(secretName, permission.getCode());

			// We need to update the existing value
			if (previous != null) {
				final Integer updated = (previous | permission.getCode()); // mask the bits with or
				this.secretPermissions.put(secretName, updated);
			}
		}
	}

	public void removePermission(final String secretName, final Permissions permission) {
		synchronized (this.secretPermissions) {
			// Get the previous value (if any)
			final Integer previous = this.secretPermissions.get(secretName);

			// We need to update the existing value
			if (previous != null) {
				final Integer updated = (previous & ~permission.getCode()); // mask the bits with and of not

				if (updated == 0) {
					this.secretPermissions.remove(secretName);
				} else {
					this.secretPermissions.put(secretName, updated);
				}
			}
		}
	}

	public boolean hasPermission(final String secretName, final Permissions permission) {
		final Integer mask = this.secretPermissions.get(secretName);
		if (mask == null) {
			return false;
		} else {
			return (mask & permission.getCode()) != 0;
		}
	}

	public void clearPermission(final String secretName) {
		this.secretPermissions.remove(secretName);
	}

	public void clearAllPermissions() {
		this.secretPermissions.clear();
	}

	protected Set<String> getSecrets() {
		return Collections.unmodifiableSet(new HashSet<String>(this.secretPermissions.keySet()));
	}
}
