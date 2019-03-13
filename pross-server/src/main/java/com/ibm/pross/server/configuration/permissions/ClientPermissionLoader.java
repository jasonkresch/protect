package com.ibm.pross.server.configuration.permissions;

import java.io.File;
import java.io.IOException;
import java.util.Collection;
import java.util.HashSet;
import java.util.Map.Entry;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

import org.ini4j.Profile;
import org.ini4j.Wini;

import com.ibm.pross.server.configuration.permissions.ClientPermissions.Permissions;

public class ClientPermissionLoader {

	public static AccessEnforcement loadIniFile(final File iniFile) throws IOException {

		System.out.println("Loading client permissions: " + iniFile.toString());

		// Load ini file
		final Wini ini = new Wini(iniFile);

		// Create map of usernames to their permissions
		final ConcurrentMap<String, ClientPermissions> permissionMap = new ConcurrentHashMap<String, ClientPermissions>();

		// Create set of all known secrets
		final Set<String> knownSecrets = new HashSet<>();

		// Iterate over each section (each section is a secret)
		final Collection<Profile.Section> secretSections = ini.values();
		for (Profile.Section secretSection : secretSections) {

			// Update set of known secrets
			final String secretName = secretSection.getName();
			knownSecrets.add(secretName);

			// Each value in this section represents a user's permission to this secret
			for (final Entry<String, String> userPermission : secretSection.entrySet()) {
				final String username = userPermission.getKey();
				final String permissions = userPermission.getValue();

				// PRint username and secret
				//System.out.print(username + "." + secretName + "\t\t = ");
				
				// Parse permissions
				final String[] permissionArray = permissions.split(",");
				//System.out.println(Arrays.toString(permissionArray));

				// Add permissions from the comma-separated list
				permissionMap.putIfAbsent(username, new ClientPermissions());
				final ClientPermissions clientPermissions = permissionMap.get(username);
				for (final String permissionString : permissionArray) {
					// Sanitize string and convert to enumeration
					final Permissions permission = Permissions.valueOf(permissionString.trim().toUpperCase());
					clientPermissions.addPermission(secretName, permission);
				}
			}
		}

		return new AccessEnforcement(permissionMap, knownSecrets);
	}

}
