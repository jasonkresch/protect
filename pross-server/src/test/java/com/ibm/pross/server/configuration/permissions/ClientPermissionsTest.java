package com.ibm.pross.server.configuration.permissions;

import java.util.HashMap;
import java.util.Map;

import org.junit.Assert;
import org.junit.Test;

import com.ibm.pross.server.configuration.permissions.ClientPermissions.Permissions;

public class ClientPermissionsTest {

	@Test
	public void testClientPermissions() {

		final ClientPermissions clientPermission = new ClientPermissions();
		Assert.assertNotNull(clientPermission);

		Assert.assertEquals(0, clientPermission.getSecrets().size());
	}

	@Test
	public void testClientPermissionsMapOfStringInteger() {

		Map<String, Integer> map = new HashMap<>();
		final String secret1 = "test1";
		final String secret2 = "test2";
		map.put(secret1, Permissions.DELETE.getCode());
		map.put(secret1, Permissions.ENABLE.getCode());
		map.put(secret2, Permissions.DISABLE.getCode());

		// Create permissions from map
		final ClientPermissions clientPermission = new ClientPermissions(map);
		Assert.assertEquals(2, clientPermission.getSecrets().size());
	}

	@Test
	public void testAddPermission() {
		final ClientPermissions clientPermission = new ClientPermissions();

		final String secret1 = "test1";
		final String secret2 = "test2";
		clientPermission.addPermission(secret1, Permissions.GENERATE);

		// Ensure only one permission impacted
		Assert.assertTrue(clientPermission.hasPermission(secret1, Permissions.GENERATE));
		Assert.assertFalse(clientPermission.hasPermission(secret2, Permissions.GENERATE));

		// Ensure no other permissions impacted
		Assert.assertFalse(clientPermission.hasPermission(secret1, Permissions.DELETE));
		Assert.assertFalse(clientPermission.hasPermission(secret1, Permissions.DISABLE));
		Assert.assertFalse(clientPermission.hasPermission(secret1, Permissions.ENABLE));
		Assert.assertFalse(clientPermission.hasPermission(secret1, Permissions.EXPONENTIATE));
		Assert.assertFalse(clientPermission.hasPermission(secret1, Permissions.INFO));
		Assert.assertFalse(clientPermission.hasPermission(secret1, Permissions.READ));
	}

	@Test
	public void testAddCombinations() {
		final ClientPermissions clientPermission = new ClientPermissions();

		final String secret1 = "test1";
		final String secret2 = "test2";

		// Add create permission
		clientPermission.addPermission(secret1, Permissions.GENERATE);

		// Ensure only one permission impacted
		Assert.assertTrue(clientPermission.hasPermission(secret1, Permissions.GENERATE));
		Assert.assertFalse(clientPermission.hasPermission(secret2, Permissions.GENERATE));

		// Ensure no other permissions impacted
		Assert.assertFalse(clientPermission.hasPermission(secret1, Permissions.DELETE));
		Assert.assertFalse(clientPermission.hasPermission(secret1, Permissions.DISABLE));
		Assert.assertFalse(clientPermission.hasPermission(secret1, Permissions.ENABLE));
		Assert.assertFalse(clientPermission.hasPermission(secret1, Permissions.EXPONENTIATE));
		Assert.assertFalse(clientPermission.hasPermission(secret1, Permissions.INFO));
		Assert.assertFalse(clientPermission.hasPermission(secret1, Permissions.READ));

		// Add delete permission
		clientPermission.addPermission(secret1, Permissions.DELETE);

		// Ensure only one permission impacted
		Assert.assertTrue(clientPermission.hasPermission(secret1, Permissions.DELETE));
		Assert.assertFalse(clientPermission.hasPermission(secret2, Permissions.DELETE));

		// Ensure no other permissions impacted
		Assert.assertFalse(clientPermission.hasPermission(secret1, Permissions.DISABLE));
		Assert.assertFalse(clientPermission.hasPermission(secret1, Permissions.ENABLE));
		Assert.assertFalse(clientPermission.hasPermission(secret1, Permissions.EXPONENTIATE));
		Assert.assertFalse(clientPermission.hasPermission(secret1, Permissions.INFO));
		Assert.assertFalse(clientPermission.hasPermission(secret1, Permissions.READ));

		// Add disable permission
		clientPermission.addPermission(secret1, Permissions.DISABLE);

		// Ensure only one permission impacted
		Assert.assertTrue(clientPermission.hasPermission(secret1, Permissions.DISABLE));
		Assert.assertFalse(clientPermission.hasPermission(secret2, Permissions.DISABLE));

		// Ensure no other permissions impacted
		Assert.assertFalse(clientPermission.hasPermission(secret1, Permissions.ENABLE));
		Assert.assertFalse(clientPermission.hasPermission(secret1, Permissions.EXPONENTIATE));
		Assert.assertFalse(clientPermission.hasPermission(secret1, Permissions.INFO));
		Assert.assertFalse(clientPermission.hasPermission(secret1, Permissions.READ));

		// Add enable permission
		clientPermission.addPermission(secret1, Permissions.ENABLE);

		// Ensure only one permission impacted
		Assert.assertTrue(clientPermission.hasPermission(secret1, Permissions.ENABLE));
		Assert.assertFalse(clientPermission.hasPermission(secret2, Permissions.ENABLE));

		// Ensure no other permissions impacted
		Assert.assertFalse(clientPermission.hasPermission(secret1, Permissions.EXPONENTIATE));
		Assert.assertFalse(clientPermission.hasPermission(secret1, Permissions.INFO));
		Assert.assertFalse(clientPermission.hasPermission(secret1, Permissions.READ));

		// Add exponentiate permission
		clientPermission.addPermission(secret1, Permissions.EXPONENTIATE);

		// Ensure only one permission impacted
		Assert.assertTrue(clientPermission.hasPermission(secret1, Permissions.EXPONENTIATE));
		Assert.assertFalse(clientPermission.hasPermission(secret2, Permissions.EXPONENTIATE));

		// Ensure no other permissions impacted
		Assert.assertFalse(clientPermission.hasPermission(secret1, Permissions.INFO));
		Assert.assertFalse(clientPermission.hasPermission(secret1, Permissions.READ));

		// Add info permission
		clientPermission.addPermission(secret1, Permissions.INFO);

		// Ensure only one permission impacted
		Assert.assertTrue(clientPermission.hasPermission(secret1, Permissions.INFO));
		Assert.assertFalse(clientPermission.hasPermission(secret2, Permissions.INFO));

		// Ensure no other permissions impacted
		Assert.assertFalse(clientPermission.hasPermission(secret1, Permissions.READ));

		// Add read permission
		clientPermission.addPermission(secret1, Permissions.READ);

		// Ensure only one permission impacted
		Assert.assertTrue(clientPermission.hasPermission(secret1, Permissions.READ));
		Assert.assertFalse(clientPermission.hasPermission(secret2, Permissions.READ));
	}

	@Test
	public void testRemovePermission() {
		ClientPermissions clientPermission = new ClientPermissions();

		final String secret1 = "test1";
		final String secret2 = "test2";
		final String secret3 = "test3";
		clientPermission.addPermission(secret1, Permissions.GENERATE);
		Assert.assertEquals(1, clientPermission.getSecrets().size());

		// Ensure only one permission impacted
		Assert.assertTrue(clientPermission.hasPermission(secret1, Permissions.GENERATE));
		Assert.assertFalse(clientPermission.hasPermission(secret2, Permissions.GENERATE));

		// Ensure no other permissions impacted
		Assert.assertFalse(clientPermission.hasPermission(secret1, Permissions.DELETE));
		Assert.assertFalse(clientPermission.hasPermission(secret1, Permissions.DISABLE));
		Assert.assertFalse(clientPermission.hasPermission(secret1, Permissions.ENABLE));
		Assert.assertFalse(clientPermission.hasPermission(secret1, Permissions.EXPONENTIATE));
		Assert.assertFalse(clientPermission.hasPermission(secret1, Permissions.INFO));
		Assert.assertFalse(clientPermission.hasPermission(secret1, Permissions.READ));

		// Test remove never-referenced secret
		clientPermission.removePermission(secret3, Permissions.GENERATE);
		Assert.assertFalse(clientPermission.hasPermission(secret3, Permissions.GENERATE));
		Assert.assertEquals(1, clientPermission.getSecrets().size());

		// Test remove non-existent secret
		clientPermission.removePermission(secret2, Permissions.GENERATE);
		Assert.assertFalse(clientPermission.hasPermission(secret2, Permissions.GENERATE));
		Assert.assertEquals(1, clientPermission.getSecrets().size());

		// Test remove non-existent permission
		clientPermission.removePermission(secret1, Permissions.INFO);
		Assert.assertFalse(clientPermission.hasPermission(secret1, Permissions.INFO));
		Assert.assertEquals(1, clientPermission.getSecrets().size());

		// Test remove existing permission
		Assert.assertTrue(clientPermission.hasPermission(secret1, Permissions.GENERATE));
		clientPermission.removePermission(secret1, Permissions.GENERATE);
		Assert.assertEquals(0, clientPermission.getSecrets().size());
		Assert.assertFalse(clientPermission.hasPermission(secret1, Permissions.GENERATE));

		// Test double remove
		Assert.assertFalse(clientPermission.hasPermission(secret1, Permissions.GENERATE));
		clientPermission.removePermission(secret1, Permissions.GENERATE);
		Assert.assertEquals(0, clientPermission.getSecrets().size());
		Assert.assertFalse(clientPermission.hasPermission(secret1, Permissions.GENERATE));
	}

	@Test
	public void testRemoveCombinations() {
		final ClientPermissions clientPermission = new ClientPermissions();

		final String secret1 = "test1";
		final String secret2 = "test2";

		// Add create permission
		clientPermission.addPermission(secret1, Permissions.GENERATE);

		// Ensure only one permission impacted
		Assert.assertTrue(clientPermission.hasPermission(secret1, Permissions.GENERATE));
		Assert.assertFalse(clientPermission.hasPermission(secret2, Permissions.GENERATE));

		// Ensure no other permissions impacted
		Assert.assertFalse(clientPermission.hasPermission(secret1, Permissions.DELETE));
		Assert.assertFalse(clientPermission.hasPermission(secret1, Permissions.DISABLE));
		Assert.assertFalse(clientPermission.hasPermission(secret1, Permissions.ENABLE));
		Assert.assertFalse(clientPermission.hasPermission(secret1, Permissions.EXPONENTIATE));
		Assert.assertFalse(clientPermission.hasPermission(secret1, Permissions.INFO));
		Assert.assertFalse(clientPermission.hasPermission(secret1, Permissions.READ));

		// Add delete permission
		clientPermission.addPermission(secret1, Permissions.DELETE);

		// Ensure only one permission impacted
		Assert.assertTrue(clientPermission.hasPermission(secret1, Permissions.DELETE));
		Assert.assertFalse(clientPermission.hasPermission(secret2, Permissions.DELETE));

		// Ensure no other permissions impacted
		Assert.assertFalse(clientPermission.hasPermission(secret1, Permissions.DISABLE));
		Assert.assertFalse(clientPermission.hasPermission(secret1, Permissions.ENABLE));
		Assert.assertFalse(clientPermission.hasPermission(secret1, Permissions.EXPONENTIATE));
		Assert.assertFalse(clientPermission.hasPermission(secret1, Permissions.INFO));
		Assert.assertFalse(clientPermission.hasPermission(secret1, Permissions.READ));

		// Add disable permission
		clientPermission.addPermission(secret1, Permissions.DISABLE);

		// Ensure only one permission impacted
		Assert.assertTrue(clientPermission.hasPermission(secret1, Permissions.DISABLE));
		Assert.assertFalse(clientPermission.hasPermission(secret2, Permissions.DISABLE));

		// Ensure no other permissions impacted
		Assert.assertFalse(clientPermission.hasPermission(secret1, Permissions.ENABLE));
		Assert.assertFalse(clientPermission.hasPermission(secret1, Permissions.EXPONENTIATE));
		Assert.assertFalse(clientPermission.hasPermission(secret1, Permissions.INFO));
		Assert.assertFalse(clientPermission.hasPermission(secret1, Permissions.READ));

		// Add enable permission
		clientPermission.addPermission(secret1, Permissions.ENABLE);

		// Ensure only one permission impacted
		Assert.assertTrue(clientPermission.hasPermission(secret1, Permissions.ENABLE));
		Assert.assertFalse(clientPermission.hasPermission(secret2, Permissions.ENABLE));

		// Ensure no other permissions impacted
		Assert.assertFalse(clientPermission.hasPermission(secret1, Permissions.EXPONENTIATE));
		Assert.assertFalse(clientPermission.hasPermission(secret1, Permissions.INFO));
		Assert.assertFalse(clientPermission.hasPermission(secret1, Permissions.READ));

		// Add exponentiate permission
		clientPermission.addPermission(secret1, Permissions.EXPONENTIATE);

		// Ensure only one permission impacted
		Assert.assertTrue(clientPermission.hasPermission(secret1, Permissions.EXPONENTIATE));
		Assert.assertFalse(clientPermission.hasPermission(secret2, Permissions.EXPONENTIATE));

		// Ensure no other permissions impacted
		Assert.assertFalse(clientPermission.hasPermission(secret1, Permissions.INFO));
		Assert.assertFalse(clientPermission.hasPermission(secret1, Permissions.READ));

		// Add info permission
		clientPermission.addPermission(secret1, Permissions.INFO);

		// Ensure only one permission impacted
		Assert.assertTrue(clientPermission.hasPermission(secret1, Permissions.INFO));
		Assert.assertFalse(clientPermission.hasPermission(secret2, Permissions.INFO));

		// Ensure no other permissions impacted
		Assert.assertFalse(clientPermission.hasPermission(secret1, Permissions.READ));

		// Add read permission
		clientPermission.addPermission(secret1, Permissions.READ);

		// Ensure only one permission impacted
		Assert.assertTrue(clientPermission.hasPermission(secret1, Permissions.READ));
		Assert.assertFalse(clientPermission.hasPermission(secret2, Permissions.READ));

		// Remove create permission
		clientPermission.removePermission(secret1, Permissions.GENERATE);

		// Ensure only one permission impacted
		Assert.assertFalse(clientPermission.hasPermission(secret1, Permissions.GENERATE));

		// Ensure no other permissions impacted
		Assert.assertTrue(clientPermission.hasPermission(secret1, Permissions.DELETE));
		Assert.assertTrue(clientPermission.hasPermission(secret1, Permissions.DISABLE));
		Assert.assertTrue(clientPermission.hasPermission(secret1, Permissions.ENABLE));
		Assert.assertTrue(clientPermission.hasPermission(secret1, Permissions.EXPONENTIATE));
		Assert.assertTrue(clientPermission.hasPermission(secret1, Permissions.INFO));
		Assert.assertTrue(clientPermission.hasPermission(secret1, Permissions.READ));
		
		// Remove delete permission
		clientPermission.removePermission(secret1, Permissions.DELETE);

		// Ensure only one permission impacted
		Assert.assertFalse(clientPermission.hasPermission(secret1, Permissions.DELETE));

		// Ensure no other permissions impacted
		Assert.assertTrue(clientPermission.hasPermission(secret1, Permissions.DISABLE));
		Assert.assertTrue(clientPermission.hasPermission(secret1, Permissions.ENABLE));
		Assert.assertTrue(clientPermission.hasPermission(secret1, Permissions.EXPONENTIATE));
		Assert.assertTrue(clientPermission.hasPermission(secret1, Permissions.INFO));
		Assert.assertTrue(clientPermission.hasPermission(secret1, Permissions.READ));
		
		// Remove disable permission
		clientPermission.removePermission(secret1, Permissions.DISABLE);

		// Ensure only one permission impacted
		Assert.assertFalse(clientPermission.hasPermission(secret1, Permissions.DISABLE));

		// Ensure no other permissions impacted
		Assert.assertTrue(clientPermission.hasPermission(secret1, Permissions.ENABLE));
		Assert.assertTrue(clientPermission.hasPermission(secret1, Permissions.EXPONENTIATE));
		Assert.assertTrue(clientPermission.hasPermission(secret1, Permissions.INFO));
		Assert.assertTrue(clientPermission.hasPermission(secret1, Permissions.READ));
		
		// Remove enable permission
		clientPermission.removePermission(secret1, Permissions.ENABLE);

		// Ensure only one permission impacted
		Assert.assertFalse(clientPermission.hasPermission(secret1, Permissions.ENABLE));

		// Ensure no other permissions impacted
		Assert.assertTrue(clientPermission.hasPermission(secret1, Permissions.EXPONENTIATE));
		Assert.assertTrue(clientPermission.hasPermission(secret1, Permissions.INFO));
		Assert.assertTrue(clientPermission.hasPermission(secret1, Permissions.READ));
		
		// Remove exponentiate permission
		clientPermission.removePermission(secret1, Permissions.EXPONENTIATE);

		// Ensure only one permission impacted
		Assert.assertFalse(clientPermission.hasPermission(secret1, Permissions.EXPONENTIATE));

		// Ensure no other permissions impacted
		Assert.assertTrue(clientPermission.hasPermission(secret1, Permissions.INFO));
		Assert.assertTrue(clientPermission.hasPermission(secret1, Permissions.READ));
		
		// Remove info permission
		clientPermission.removePermission(secret1, Permissions.INFO);

		// Ensure only one permission impacted
		Assert.assertFalse(clientPermission.hasPermission(secret1, Permissions.INFO));

		// Ensure no other permissions impacted
		Assert.assertTrue(clientPermission.hasPermission(secret1, Permissions.READ));
		
		// Remove read permission
		clientPermission.removePermission(secret1, Permissions.READ);

		// Ensure only one permission impacted
		Assert.assertFalse(clientPermission.hasPermission(secret1, Permissions.READ));

		// Ensure no other permissions impacted
		Assert.assertFalse(clientPermission.hasPermission(secret1, Permissions.READ));
		
		// Ensure all permissions unset
		Assert.assertFalse(clientPermission.hasPermission(secret1, Permissions.GENERATE));
		Assert.assertFalse(clientPermission.hasPermission(secret1, Permissions.DELETE));
		Assert.assertFalse(clientPermission.hasPermission(secret1, Permissions.DISABLE));
		Assert.assertFalse(clientPermission.hasPermission(secret1, Permissions.ENABLE));
		Assert.assertFalse(clientPermission.hasPermission(secret1, Permissions.EXPONENTIATE));
		Assert.assertFalse(clientPermission.hasPermission(secret1, Permissions.INFO));
		Assert.assertFalse(clientPermission.hasPermission(secret1, Permissions.READ));
		
		// Ensure no memory leak
		Assert.assertEquals(0, clientPermission.getSecrets().size());
	}

	@Test
	public void testClearPermission() {
		final ClientPermissions clientPermission = new ClientPermissions();
		Assert.assertEquals(0, clientPermission.getSecrets().size());

		final String secret1 = "test1";
		final String secret2 = "test2";
		
		clientPermission.addPermission(secret1, Permissions.GENERATE);
		Assert.assertEquals(1, clientPermission.getSecrets().size());
		
		clientPermission.addPermission(secret1, Permissions.DELETE);
		Assert.assertEquals(1, clientPermission.getSecrets().size());
		
		clientPermission.addPermission(secret2, Permissions.GENERATE);
		Assert.assertEquals(2, clientPermission.getSecrets().size());
		
		clientPermission.clearPermission(secret1);
		Assert.assertEquals(1, clientPermission.getSecrets().size());
		
		clientPermission.clearPermission("none");
		Assert.assertEquals(1, clientPermission.getSecrets().size());
		
		clientPermission.clearPermission(secret2);
		Assert.assertEquals(0, clientPermission.getSecrets().size());
	}

	@Test
	public void testClearAllPermissions() {
		final ClientPermissions clientPermission = new ClientPermissions();
		Assert.assertEquals(0, clientPermission.getSecrets().size());

		final String secret1 = "test1";
		final String secret2 = "test2";
		
		clientPermission.addPermission(secret1, Permissions.GENERATE);
		Assert.assertEquals(1, clientPermission.getSecrets().size());
		
		clientPermission.addPermission(secret1, Permissions.DELETE);
		Assert.assertEquals(1, clientPermission.getSecrets().size());
		
		clientPermission.addPermission(secret2, Permissions.GENERATE);
		Assert.assertEquals(2, clientPermission.getSecrets().size());
		
		clientPermission.clearAllPermissions();
		Assert.assertEquals(0, clientPermission.getSecrets().size());
	}

}
