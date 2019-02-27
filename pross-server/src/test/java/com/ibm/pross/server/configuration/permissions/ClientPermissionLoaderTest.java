package com.ibm.pross.server.configuration.permissions;

import java.io.File;
import java.io.IOException;

import org.junit.Assert;
import org.junit.Test;

import com.ibm.pross.server.configuration.permissions.ClientPermissions.Permissions;
import com.ibm.pross.server.configuration.permissions.exceptions.NotFoundException;
import com.ibm.pross.server.configuration.permissions.exceptions.UnauthorizedException;

public class ClientPermissionLoaderTest {

	// Secrets
	public static final String prfSecret = "prf-secret";
	public static final String mySecret = "my-secret";

	// Users
	public static final Integer admin = 1;
	public static final Integer secOfficer = 2;
	public static final Integer expUser = 3;
	public static final Integer storeUser = 4;

	@Test
	public void testNotFoundSecret() throws IOException, UnauthorizedException, NotFoundException {

		final AccessEnforcement accessEnforcement = ClientPermissionLoader
				.load(new File("config/client/clients.config"));

		Assert.assertNotNull(accessEnforcement);

		try {
			accessEnforcement.enforceAccess(admin, "no-such-secret", Permissions.GENERATE);
			Assert.fail("Expected not found exception");
		} catch (NotFoundException expected) {

		}
	}

	@Test
	public void testAdminPermissions() throws IOException, UnauthorizedException, NotFoundException {

		final AccessEnforcement accessEnforcement = ClientPermissionLoader
				.load(new File("config/client/clients.config"));

		Assert.assertNotNull(accessEnforcement);

		// Check admin permissions for PRF Secret
		accessEnforcement.enforceAccess(admin, prfSecret, Permissions.GENERATE);
		accessEnforcement.enforceAccess(admin, prfSecret, Permissions.DELETE);
		accessEnforcement.enforceAccess(admin, prfSecret, Permissions.ENABLE);
		accessEnforcement.enforceAccess(admin, prfSecret, Permissions.DISABLE);
		accessEnforcement.enforceAccess(admin, prfSecret, Permissions.INFO);
		try {
			accessEnforcement.enforceAccess(admin, prfSecret, Permissions.EXPONENTIATE);
			Assert.fail("Expected unauthorized exception");
		} catch (UnauthorizedException expected) {
		}
		try {
			accessEnforcement.enforceAccess(admin, prfSecret, Permissions.STORE);
			Assert.fail("Expected unauthorized exception");
		} catch (UnauthorizedException expected) {
		}
		try {
			accessEnforcement.enforceAccess(admin, prfSecret, Permissions.READ);
			Assert.fail("Expected unauthorized exception");
		} catch (UnauthorizedException expected) {
		}
		try {
			accessEnforcement.enforceAccess(admin, prfSecret, Permissions.RSA_SIGN);
			Assert.fail("Expected unauthorized exception");
		} catch (UnauthorizedException expected) {
		}

		// Check admin permissions for Store secret
		accessEnforcement.enforceAccess(admin, mySecret, Permissions.DELETE);
		accessEnforcement.enforceAccess(admin, mySecret, Permissions.ENABLE);
		accessEnforcement.enforceAccess(admin, mySecret, Permissions.DISABLE);
		accessEnforcement.enforceAccess(admin, mySecret, Permissions.INFO);
		try {
			accessEnforcement.enforceAccess(admin, mySecret, Permissions.GENERATE);
			Assert.fail("Expected unauthorized exception");
		} catch (UnauthorizedException expected) {
		}
		try {
			accessEnforcement.enforceAccess(admin, mySecret, Permissions.EXPONENTIATE);
			Assert.fail("Expected unauthorized exception");
		} catch (UnauthorizedException expected) {
		}
		try {
			accessEnforcement.enforceAccess(admin, mySecret, Permissions.STORE);
			Assert.fail("Expected unauthorized exception");
		} catch (UnauthorizedException expected) {
		}
		try {
			accessEnforcement.enforceAccess(admin, mySecret, Permissions.READ);
			Assert.fail("Expected unauthorized exception");
		} catch (UnauthorizedException expected) {
		}
		try {
			accessEnforcement.enforceAccess(admin, mySecret, Permissions.RSA_SIGN);
			Assert.fail("Expected unauthorized exception");
		} catch (UnauthorizedException expected) {
		}
	}

	@Test
	public void testSecOfficerPermissions() throws IOException, UnauthorizedException, NotFoundException {

		final AccessEnforcement accessEnforcement = ClientPermissionLoader
				.load(new File("config/client/clients.config"));

		Assert.assertNotNull(accessEnforcement);
		// Check sec officer permissions for PRF Secret
		accessEnforcement.enforceAccess(secOfficer, prfSecret, Permissions.DISABLE);
		accessEnforcement.enforceAccess(secOfficer, prfSecret, Permissions.INFO);
		try {
			accessEnforcement.enforceAccess(secOfficer, prfSecret, Permissions.GENERATE);
			Assert.fail("Expected unauthorized exception");
		} catch (UnauthorizedException expected) {
		}
		try {
			accessEnforcement.enforceAccess(secOfficer, prfSecret, Permissions.DELETE);
			Assert.fail("Expected unauthorized exception");
		} catch (UnauthorizedException expected) {
		}
		try {
			accessEnforcement.enforceAccess(secOfficer, prfSecret, Permissions.ENABLE);
			Assert.fail("Expected unauthorized exception");
		} catch (UnauthorizedException expected) {
		}
		try {
			accessEnforcement.enforceAccess(secOfficer, prfSecret, Permissions.EXPONENTIATE);
			Assert.fail("Expected unauthorized exception");
		} catch (UnauthorizedException expected) {
		}
		try {
			accessEnforcement.enforceAccess(secOfficer, prfSecret, Permissions.STORE);
			Assert.fail("Expected unauthorized exception");
		} catch (UnauthorizedException expected) {
		}
		try {
			accessEnforcement.enforceAccess(secOfficer, prfSecret, Permissions.READ);
			Assert.fail("Expected unauthorized exception");
		} catch (UnauthorizedException expected) {
		}
		try {
			accessEnforcement.enforceAccess(secOfficer, prfSecret, Permissions.RSA_SIGN);
			Assert.fail("Expected unauthorized exception");
		} catch (UnauthorizedException expected) {
		}

		// Check sec officer permissions for Store secret
		accessEnforcement.enforceAccess(secOfficer, mySecret, Permissions.DISABLE);
		accessEnforcement.enforceAccess(secOfficer, mySecret, Permissions.INFO);
		try {
			accessEnforcement.enforceAccess(secOfficer, mySecret, Permissions.GENERATE);
			Assert.fail("Expected unauthorized exception");
		} catch (UnauthorizedException expected) {
		}
		try {
			accessEnforcement.enforceAccess(secOfficer, mySecret, Permissions.DELETE);
			Assert.fail("Expected unauthorized exception");
		} catch (UnauthorizedException expected) {
		}
		try {
			accessEnforcement.enforceAccess(secOfficer, mySecret, Permissions.ENABLE);
			Assert.fail("Expected unauthorized exception");
		} catch (UnauthorizedException expected) {
		}
		try {
			accessEnforcement.enforceAccess(secOfficer, mySecret, Permissions.EXPONENTIATE);
			Assert.fail("Expected unauthorized exception");
		} catch (UnauthorizedException expected) {
		}
		try {
			accessEnforcement.enforceAccess(secOfficer, mySecret, Permissions.STORE);
			Assert.fail("Expected unauthorized exception");
		} catch (UnauthorizedException expected) {
		}
		try {
			accessEnforcement.enforceAccess(secOfficer, mySecret, Permissions.READ);
			Assert.fail("Expected unauthorized exception");
		} catch (UnauthorizedException expected) {
		}
		try {
			accessEnforcement.enforceAccess(secOfficer, mySecret, Permissions.RSA_SIGN);
			Assert.fail("Expected unauthorized exception");
		} catch (UnauthorizedException expected) {
		}
	}

	@Test
	public void testExpUserPermissions() throws IOException, UnauthorizedException, NotFoundException {

		final AccessEnforcement accessEnforcement = ClientPermissionLoader
				.load(new File("config/client/clients.config"));

		Assert.assertNotNull(accessEnforcement);

		// Checkexp user permissions for PRF Secret
		accessEnforcement.enforceAccess(expUser, prfSecret, Permissions.EXPONENTIATE);
		accessEnforcement.enforceAccess(expUser, prfSecret, Permissions.INFO);
		try {
			accessEnforcement.enforceAccess(expUser, prfSecret, Permissions.GENERATE);
			Assert.fail("Expected unauthorized exception");
		} catch (UnauthorizedException expected) {
		}
		try {
			accessEnforcement.enforceAccess(expUser, prfSecret, Permissions.DELETE);
			Assert.fail("Expected unauthorized exception");
		} catch (UnauthorizedException expected) {
		}
		try {
			accessEnforcement.enforceAccess(expUser, prfSecret, Permissions.ENABLE);
			Assert.fail("Expected unauthorized exception");
		} catch (UnauthorizedException expected) {
		}
		try {
			accessEnforcement.enforceAccess(expUser, prfSecret, Permissions.DISABLE);
			Assert.fail("Expected unauthorized exception");
		} catch (UnauthorizedException expected) {
		}
		try {
			accessEnforcement.enforceAccess(expUser, prfSecret, Permissions.STORE);
			Assert.fail("Expected unauthorized exception");
		} catch (UnauthorizedException expected) {
		}
		try {
			accessEnforcement.enforceAccess(expUser, prfSecret, Permissions.READ);
			Assert.fail("Expected unauthorized exception");
		} catch (UnauthorizedException expected) {
		}
		try {
			accessEnforcement.enforceAccess(expUser, prfSecret, Permissions.RSA_SIGN);
			Assert.fail("Expected unauthorized exception");
		} catch (UnauthorizedException expected) {
		}

		// Check exp user permissions for Store secret
		try {
			accessEnforcement.enforceAccess(expUser, mySecret, Permissions.GENERATE);
			Assert.fail("Expected unauthorized exception");
		} catch (UnauthorizedException expected) {
		}
		try {
			accessEnforcement.enforceAccess(expUser, mySecret, Permissions.DISABLE);
			Assert.fail("Expected unauthorized exception");
		} catch (UnauthorizedException expected) {
		}
		try {
			accessEnforcement.enforceAccess(expUser, mySecret, Permissions.INFO);
			Assert.fail("Expected unauthorized exception");
		} catch (UnauthorizedException expected) {
		}
		try {
			accessEnforcement.enforceAccess(expUser, mySecret, Permissions.DELETE);
			Assert.fail("Expected unauthorized exception");
		} catch (UnauthorizedException expected) {
		}
		try {
			accessEnforcement.enforceAccess(expUser, mySecret, Permissions.ENABLE);
			Assert.fail("Expected unauthorized exception");
		} catch (UnauthorizedException expected) {
		}
		try {
			accessEnforcement.enforceAccess(expUser, mySecret, Permissions.EXPONENTIATE);
			Assert.fail("Expected unauthorized exception");
		} catch (UnauthorizedException expected) {
		}
		try {
			accessEnforcement.enforceAccess(expUser, mySecret, Permissions.STORE);
			Assert.fail("Expected unauthorized exception");
		} catch (UnauthorizedException expected) {
		}
		try {
			accessEnforcement.enforceAccess(expUser, mySecret, Permissions.READ);
			Assert.fail("Expected unauthorized exception");
		} catch (UnauthorizedException expected) {
		}
		try {
			accessEnforcement.enforceAccess(expUser, mySecret, Permissions.RSA_SIGN);
			Assert.fail("Expected unauthorized exception");
		} catch (UnauthorizedException expected) {
		}
	}

	@Test
	public void testStoreUserPermissions() throws IOException, UnauthorizedException, NotFoundException {

		final AccessEnforcement accessEnforcement = ClientPermissionLoader
				.load(new File("config/client/clients.config"));

		Assert.assertNotNull(accessEnforcement);

		// Checkexp user permissions for PRF Secret
		accessEnforcement.enforceAccess(storeUser, mySecret, Permissions.STORE);
		accessEnforcement.enforceAccess(storeUser, mySecret, Permissions.READ);
		accessEnforcement.enforceAccess(storeUser, mySecret, Permissions.DELETE);
		accessEnforcement.enforceAccess(storeUser, mySecret, Permissions.INFO);
		try {
			accessEnforcement.enforceAccess(storeUser, mySecret, Permissions.GENERATE);
			Assert.fail("Expected unauthorized exception");
		} catch (UnauthorizedException expected) {
		}
		try {
			accessEnforcement.enforceAccess(storeUser, mySecret, Permissions.ENABLE);
			Assert.fail("Expected unauthorized exception");
		} catch (UnauthorizedException expected) {
		}
		try {
			accessEnforcement.enforceAccess(storeUser, mySecret, Permissions.DISABLE);
			Assert.fail("Expected unauthorized exception");
		} catch (UnauthorizedException expected) {
		}
		try {
			accessEnforcement.enforceAccess(storeUser, mySecret, Permissions.EXPONENTIATE);
			Assert.fail("Expected unauthorized exception");
		} catch (UnauthorizedException expected) {
		}
		try {
			accessEnforcement.enforceAccess(storeUser, mySecret, Permissions.RSA_SIGN);
			Assert.fail("Expected unauthorized exception");
		} catch (UnauthorizedException expected) {
		}

		// Check exp user permissions for Store secret
		try {
			accessEnforcement.enforceAccess(storeUser, prfSecret, Permissions.GENERATE);
			Assert.fail("Expected unauthorized exception");
		} catch (UnauthorizedException expected) {
		}
		try {
			accessEnforcement.enforceAccess(storeUser, prfSecret, Permissions.DISABLE);
			Assert.fail("Expected unauthorized exception");
		} catch (UnauthorizedException expected) {
		}
		try {
			accessEnforcement.enforceAccess(storeUser, prfSecret, Permissions.INFO);
			Assert.fail("Expected unauthorized exception");
		} catch (UnauthorizedException expected) {
		}
		try {
			accessEnforcement.enforceAccess(storeUser, prfSecret, Permissions.DELETE);
			Assert.fail("Expected unauthorized exception");
		} catch (UnauthorizedException expected) {
		}
		try {
			accessEnforcement.enforceAccess(storeUser, prfSecret, Permissions.ENABLE);
			Assert.fail("Expected unauthorized exception");
		} catch (UnauthorizedException expected) {
		}
		try {
			accessEnforcement.enforceAccess(storeUser, prfSecret, Permissions.EXPONENTIATE);
			Assert.fail("Expected unauthorized exception");
		} catch (UnauthorizedException expected) {
		}
		try {
			accessEnforcement.enforceAccess(storeUser, prfSecret, Permissions.STORE);
			Assert.fail("Expected unauthorized exception");
		} catch (UnauthorizedException expected) {
		}
		try {
			accessEnforcement.enforceAccess(storeUser, prfSecret, Permissions.READ);
			Assert.fail("Expected unauthorized exception");
		} catch (UnauthorizedException expected) {
		}
		try {
			accessEnforcement.enforceAccess(storeUser, prfSecret, Permissions.RSA_SIGN);
			Assert.fail("Expected unauthorized exception");
		} catch (UnauthorizedException expected) {
		}
	}

}
