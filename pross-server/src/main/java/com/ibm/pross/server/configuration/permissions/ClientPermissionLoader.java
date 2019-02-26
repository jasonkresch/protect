package com.ibm.pross.server.configuration.permissions;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.Arrays;
import java.util.Properties;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

import com.ibm.pross.server.configuration.permissions.ClientPermissions.Permissions;

public class ClientPermissionLoader {

	public static AccessEnforcement load(final File configFile) throws IOException {

		System.out.println("Loading client permissions: " + configFile.toString());
		
		final Properties properties = new Properties();

		try (final FileInputStream inputStream = new FileInputStream(configFile);) {

			// Load the properties file
			properties.load(inputStream);

			// Create map of client ids to their permissions
			final ConcurrentMap<Integer, ClientPermissions> permissionMap = new ConcurrentHashMap<Integer, ClientPermissions>();

			// Populate map using permission entries
			for (final String key : properties.stringPropertyNames()) {

				// Parse the key into a client id and secret name
				System.out.print(key + "\t=\t");
				final String[] keyParts = key.split("\\.");
				final Integer clientId = Integer.parseInt(keyParts[0]);
				final String secretName = keyParts[1];

				// Parse the permission list
				final String permissions = properties.getProperty(key);
				final String[] permissionArray = permissions.split(",");
				System.out.println(Arrays.toString(permissionArray));

				// Add permissions from the comma-separated list
				permissionMap.putIfAbsent(clientId, new ClientPermissions());
				final ClientPermissions clientPermissions = permissionMap.get(clientId);
				for (final String permissionString : permissionArray) {
					// Sanitize string and convert to enumeration
					final Permissions permission = Permissions.valueOf(permissionString.trim().toUpperCase());
					clientPermissions.addPermission(secretName, permission);
				}

			}

			return new AccessEnforcement(permissionMap);
		}
	}

}
