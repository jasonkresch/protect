package com.ibm.pross.server.configuration.permissions;

import java.util.Collections;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

import com.ibm.pross.server.configuration.permissions.ClientPermissions.Permissions;

public class AccessEnforcement {

	private final ConcurrentMap<Integer, ClientPermissions> permissionMap;

	public AccessEnforcement(final Map<Integer, ClientPermissions> permissionMap) {
		this.permissionMap = new ConcurrentHashMap<>(permissionMap);
	}

	public void enforceAccess(final Integer clientId, final String secretName, final Permissions permission)
			throws UnauthorizedException {

		// Get this client's permissions
		final ClientPermissions clientPermissions = this.permissionMap.get(clientId);

		if (clientPermissions == null) {
			// Client is unknown
			throw new UnauthorizedException();
		} else {
			// Client is known but is not authorized
			if (!clientPermissions.hasPermission(secretName, permission)) {
				throw new UnauthorizedException();
			}
		}
	}

	private static final class DummyAccessEnforcement extends AccessEnforcement {

		public DummyAccessEnforcement() {
			super(Collections.emptyMap());
		}

		@Override
		public void enforceAccess(final Integer clientId, final String secretName, final Permissions permission)
				throws UnauthorizedException {
			// Always allow
		}
	}

	@Deprecated
	public static final AccessEnforcement INSECURE_DUMMY_ENFORCEMENT = new DummyAccessEnforcement();


}
