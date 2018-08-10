/*
 * Copyright (c) IBM Corporation 2018. All Rights Reserved.
 * Project name: pross
 * This project is licensed under the MIT License, see LICENSE.
 */

package com.ibm.pross.common.util.crypto.kdf;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.Security;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.DecoderException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Ignore;
import org.junit.Test;

import com.ibm.pross.common.util.RandomNumberGenerator;
import com.ibm.pross.common.util.crypto.ecc.EcCurve;
import com.ibm.pross.common.util.crypto.ecc.EcPoint;
import com.ibm.pross.common.util.serialization.HexUtil;

public class TwoHashTDFTest {

	private static final byte[] AES_256_KEY = "aes-256-key".getBytes(StandardCharsets.UTF_8);
	private static final byte[] AES_GCM_IV = "aes-gcm-iv".getBytes(StandardCharsets.UTF_8);

	@BeforeClass
	public static void setupBeforeClass()
	{
		Security.addProvider(new BouncyCastleProvider());
	}
	
	
	@Ignore
	@Test
	public void testGenerateParameters() {
		//byte[] keyID = Randomization.generateRandomBytes(256);
		byte[] keyID = RandomNumberGenerator.generateRandomBytes(1024);
		byte[] plaintext = RandomNumberGenerator.generateRandomBytes(65 * 8);
		EcPoint point = EcCurve.secp521r1.getPointHasher().hashToCurve(RandomNumberGenerator.generateRandomBytes(256));

		System.out.println(HexUtil.binToHex(keyID));
		System.out.println(HexUtil.binToHex(plaintext));
		System.out.println(point);
	}

	private Cipher getCipher(final byte[] keyBytes, final byte[] ivBytes) throws GeneralSecurityException {

		// Create Cipher
		final Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
		final SecretKeySpec keySpec = new SecretKeySpec(keyBytes, "AES");
		final GCMParameterSpec gcmSpec = new GCMParameterSpec(96, ivBytes);
		cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmSpec);

		return cipher;
	}

	// Test Vector 01: curve secp256k1, short key id, encryption
	@Test
	public void testVector01() throws GeneralSecurityException, DecoderException {

		final byte[] keyIdentifier = HexUtil.hexToBin("ad969609100a1b4fedf074d4f6794acf5568df5322ae16285504ee5452aa7d84");
		final byte[] plaintext = HexUtil.hexToBin(
				"5136322df0b4779ed6e89ee4df8381691bbfa937cec5301f94360b404e49a989dba57f6cc2b8195381b87396cee44bf75bf910a9ecd1d49c8ed329cc45a75f8372");

		final EcPoint derivedKey = new EcPoint(
				"9737069411621496258337607220832231323058362049599360980565321179914165510846",
				"14035384688270690088656577138655796542863776259101869272245820158150091862789");

		// Test PRF key derived as OPRF output
		HmacKeyDerivationFunction hkdf = EntropyExtractor.getKeyGenerator(keyIdentifier, derivedKey);
		System.out.println(HexUtil.binToHex(hkdf.getPrfKey()));
		Assert.assertEquals(
						"726652fef8c75b038d51d72454a75e46bf0a80c02d7070a314aea82798cada8026452761124e807de1ea719c901c5189944c0c371678d514f9b43ba8bbbadb7e",
						HexUtil.binToHex(hkdf.getPrfKey()));

		// Generate AES key
		final byte[] keyBytes = hkdf.createKey(AES_256_KEY, 32);
		System.out.println(HexUtil.binToHex(keyBytes));
		Assert.assertEquals(
				"083e2899ac74521e8188537c9cfc8ba1b5e794830d635a88bc40f66fdbf8c9b6",
				HexUtil.binToHex(keyBytes));

		// Generate AES IV
		final byte[] ivBytes = hkdf.createKey(AES_GCM_IV, 12);
		System.out.println(HexUtil.binToHex(ivBytes));
		Assert.assertEquals(
				"6933419a1067ec2a04d6aedb",
				HexUtil.binToHex(ivBytes));

		// Create Cipher
		final Cipher cipher = getCipher(keyBytes, ivBytes);
		final byte[] cipherText = cipher.doFinal(plaintext);
		Assert.assertEquals(plaintext.length + ivBytes.length, cipherText.length);
		
		System.out.println(HexUtil.binToHex(cipherText));
		Assert.assertEquals(
				"02871bca3bb0fa68f0a7e0a2423e61d2214d6001854db4b9f4531dd442725087d7756208e02bb6b8f7d4267684abfbf7197436845944720fa072c6e90e66eba1204f7232042038e456efc76051",
				HexUtil.binToHex(cipherText));
	}

	// Test Vector 02: curve secp256k1, long key id, encryption
	@Test
	public void testVector02() throws GeneralSecurityException, DecoderException {

		final byte[] keyIdentifier = HexUtil.hexToBin("144ac2ee4183b925dc41788c0ea4afbd57a13664191c4069cb6f59a6923cb75f708b0333c1d8e88bcbbca7dd91686947d2cc41b121c522657d79f2a6a264a4718aeec71eeed77d7ca8935c6dcfea4ac022aec33f2f6b2093d3370e27bf43e535b45e23389e2c0f2f507a81283f07247582dd7a2d3b66169201d617fbefbda48f");
		final byte[] plaintext = HexUtil.hexToBin(
				"794bc99342977413b839ebb4478e71ff7ba4cd695196ea5253b0faf893fbe420291e1fbb7c62366cfd6694ea0a728311972a47c442da63e3362ece36cce9031144");

		final EcPoint derivedKey = new EcPoint(
				"46195358122532340173598016822926826423730709791718488819601810006099599281683",
				"95564052694736849019612877696172636682357859588536149620010875687863406710730");

		// Test PRF key derived as OPRF output
		HmacKeyDerivationFunction hkdf = EntropyExtractor.getKeyGenerator(keyIdentifier, derivedKey);
		System.out.println(HexUtil.binToHex(hkdf.getPrfKey()));
		Assert.assertEquals(
						"c409762a3c65352de827c9811cfc7ced936144561e2c2d1e61f542da99f3b9906155bffc232a48d6673ed21a1e23f1aad7988441f6e0498af4a2265426a37fc0",
						HexUtil.binToHex(hkdf.getPrfKey()));

		// Generate AES key
		final byte[] keyBytes = hkdf.createKey(AES_256_KEY, 32);
		System.out.println(HexUtil.binToHex(keyBytes));
		Assert.assertEquals(
				"e1c5c0bc901c44d73debb84a294137b858ae2b36a92044c1f428608309cd9cc8",
				HexUtil.binToHex(keyBytes));

		// Generate AES IV
		final byte[] ivBytes = hkdf.createKey(AES_GCM_IV, 12);
		System.out.println(HexUtil.binToHex(ivBytes));
		Assert.assertEquals(
				"de990068f7c7b12ec99ba67d",
				HexUtil.binToHex(ivBytes));

		// Create Cipher
		final Cipher cipher = getCipher(keyBytes, ivBytes);
		final byte[] cipherText = cipher.doFinal(plaintext);
		Assert.assertEquals(plaintext.length + ivBytes.length, cipherText.length);
		
		System.out.println(HexUtil.binToHex(cipherText));
		Assert.assertEquals(
				"78c65227d4ce38ef9e32c578c16f6dae0a500d9dc8dc0b718cd71ef38993c286424035392725dd4c78743f8aa70a1f46d078626c7337014c8efcaedc7d166c6dc414845e8625dcb240e6923f77",
				HexUtil.binToHex(cipherText));
	}

	// Test Vector 03: curve secp256r1, short key id, encryption
	@Test
	public void testVector03() throws GeneralSecurityException, DecoderException {


		final byte[] keyIdentifier = HexUtil.hexToBin("8ccfb04a0ba243be2056466e3f7d9a3da354e1ecfaa995f69ddc7c3fe2c01090");
		final byte[] plaintext = HexUtil.hexToBin(
				"7bec10639d38ae63cfdb32f15245ed63ee7f886d0c5d7c7d9e50b55eba8858891786d5abada7c42092025dfb8223c77b6ea0bd4e4232bdf73dc609cb3b95d58d67");

		final EcPoint derivedKey = new EcPoint(
				"41125754360786451934584599020238120266940844755721793019364288414604190118803",
				"12609315265990135540344286271316485114661201820431620165220562645197340112594");

		// Test PRF key derived as OPRF output
		HmacKeyDerivationFunction hkdf = EntropyExtractor.getKeyGenerator(keyIdentifier, derivedKey);
		System.out.println(HexUtil.binToHex(hkdf.getPrfKey()));
		Assert.assertEquals(
						"a210de341424c3b0cdbdb43ea27887174acac3d6842159991f817cd3abcdf70e058acad162425caa4732765441a2d0137b7ca2ab8bb66684551ed87bc1f73c45",
						HexUtil.binToHex(hkdf.getPrfKey()));

		// Generate AES key
		final byte[] keyBytes = hkdf.createKey(AES_256_KEY, 32);
		System.out.println(HexUtil.binToHex(keyBytes));
		Assert.assertEquals(
				"77fb4b464efe8d979897946d24b05e93b57e0df0b73b6f683acc32e0e44c3170",
				HexUtil.binToHex(keyBytes));

		// Generate AES IV
		final byte[] ivBytes = hkdf.createKey(AES_GCM_IV, 12);
		System.out.println(HexUtil.binToHex(ivBytes));
		Assert.assertEquals(
				"3cf4c913dbb1a2925d5491a1",
				HexUtil.binToHex(ivBytes));

		// Create Cipher
		final Cipher cipher = getCipher(keyBytes, ivBytes);
		final byte[] cipherText = cipher.doFinal(plaintext);
		Assert.assertEquals(plaintext.length + ivBytes.length, cipherText.length);
		
		System.out.println(HexUtil.binToHex(cipherText));
		Assert.assertEquals(
				"03ff8accf751441d0f0cd6f34856b90b9158c483f9dca02e19072d236e285c16522af2f44ed91beb53ccb9b894460bf23aba9af8a260bf6419fd2f422b11579538228495c0b97d1c3c36b65115",
				HexUtil.binToHex(cipherText));
		
	}

	// Test Vector 04: curve secp256r1, long key id, encryption
	@Test
	public void testVector04() throws GeneralSecurityException, DecoderException {


		final byte[] keyIdentifier = HexUtil.hexToBin("c9a929f30c96d44ed84f187a01afab3ee74f299e5859ec376202ce1d3b39b2ab13fa76ad83cf3a86fc5385a97a90767eb0b71c5383e4353c237ee51ad2b85a1ef11ae4164b875a19367136f53dd416ca40f767202e6abbb6980b2ca1db4e7aea4a34e50cd1c0759cb6d7fded62cffbb761ae1d902b7beec6b0eaa56e002cedbb");
		final byte[] plaintext = HexUtil.hexToBin(
				"a27c683c859af9f88ce39076f62ba72f36bc46dc1254d3ffd506a4343007f21282d05b4efcad5359ebd0d6a79124acaf8cb26546c9a3fbf25d4c5eebc2897ba1fa");

		final EcPoint derivedKey = new EcPoint(
				"1388542547207991378065083673766753440363781612522013217889944459493698276055",
				"7360137927352770859876871132433702518691793839027205621992979400036929351439");

		// Test PRF key derived as OPRF output
		HmacKeyDerivationFunction hkdf = EntropyExtractor.getKeyGenerator(keyIdentifier, derivedKey);
		System.out.println(HexUtil.binToHex(hkdf.getPrfKey()));
		Assert.assertEquals(
						"5553546d75c347ab842c54c7c490db5b69d129e743bd090a3f58f60d5b5d583bca74d8cb91949efbeb33e0a1a1303994aefa5fb5923cbd6118ec6e74ada70d17",
						HexUtil.binToHex(hkdf.getPrfKey()));

		// Generate AES key
		final byte[] keyBytes = hkdf.createKey(AES_256_KEY, 32);
		System.out.println(HexUtil.binToHex(keyBytes));
		Assert.assertEquals(
				"ffba48cec3298b25016da432569a2088cb158dd06c1fce3933cdaa5a57090dc8",
				HexUtil.binToHex(keyBytes));

		// Generate AES IV
		final byte[] ivBytes = hkdf.createKey(AES_GCM_IV, 12);
		System.out.println(HexUtil.binToHex(ivBytes));
		Assert.assertEquals(
				"6e60c7923bf8c26fcd18afb6",
				HexUtil.binToHex(ivBytes));

		// Create Cipher
		final Cipher cipher = getCipher(keyBytes, ivBytes);
		final byte[] cipherText = cipher.doFinal(plaintext);
		Assert.assertEquals(plaintext.length + ivBytes.length, cipherText.length);
		
		System.out.println(HexUtil.binToHex(cipherText));
		Assert.assertEquals(
				"bf59a19b7991ae75a6003943067071594ee147d9e430d9baf50238897838b3ab41778c12eea3640dd3230d8bf315c54cabab96b16a10c6ad211777340543964bac2486bb537304f52929c59105",
				HexUtil.binToHex(cipherText));
	}

	// Test Vector 05: curve secp384r1, short key id, encryption
	@Test
	public void testVector05() throws GeneralSecurityException, DecoderException {

		final byte[] keyIdentifier = HexUtil.hexToBin("1c380ff905192e430022bca190cbe82841e2b1c2f8acd793b5ca94ba49b94577");
		final byte[] plaintext = HexUtil.hexToBin(
				"3b6f326e062fba65fdc02f8174afce3c8d235069ac8cda733060376ebfe8ab244e43149ed8325f6a6ee1fff155d83ae0fabee63b4f2493f780dc60be1eb7ffeadd");

		final EcPoint derivedKey = new EcPoint(
				"25842518164557873376255039729948506088996299103705406632711690371899146984514413271304422922814152290098963704456588",
				"32638162191189958696639941284076848440410602223902957065826399072642666125026901646148040086483782276416423350847813");

		// Test PRF key derived as OPRF output
		HmacKeyDerivationFunction hkdf = EntropyExtractor.getKeyGenerator(keyIdentifier, derivedKey);
		System.out.println(HexUtil.binToHex(hkdf.getPrfKey()));
		Assert.assertEquals(
						"b3ed1338db25b1666670c3f83cee9a0fbc8c6a907c9088f67348c0004e13be982847b7ecdd416ffde3a1e169c0ebf691c56a64dc77e7c0e8996561d91e87c21c",
						HexUtil.binToHex(hkdf.getPrfKey()));

		// Generate AES key
		final byte[] keyBytes = hkdf.createKey(AES_256_KEY, 32);
		System.out.println(HexUtil.binToHex(keyBytes));
		Assert.assertEquals(
				"a95eeeca1342ba575cd95d273755537077b509f1e443bacc2ada44ba11897e8b",
				HexUtil.binToHex(keyBytes));

		// Generate AES IV
		final byte[] ivBytes = hkdf.createKey(AES_GCM_IV, 12);
		System.out.println(HexUtil.binToHex(ivBytes));
		Assert.assertEquals(
				"36b2f4a0308ded0c87318409",
				HexUtil.binToHex(ivBytes));

		// Create Cipher
		final Cipher cipher = getCipher(keyBytes, ivBytes);
		final byte[] cipherText = cipher.doFinal(plaintext);
		Assert.assertEquals(plaintext.length + ivBytes.length, cipherText.length);
		
		System.out.println(HexUtil.binToHex(cipherText));
		Assert.assertEquals(
				"1724b7de571adc80b85abb188a871fa473904cfc184cbb09d6812d0149e8c07eeaba5049fabb3f77aebb1e524c29416a6cf813e775fd4a4a6daf778a70eb159efcd4f00c56cebe3e93c163c3b5",
				HexUtil.binToHex(cipherText));
	}

	// Test Vector 06: curve secp384r1, long key id, encryption
	@Test
	public void testVector06() throws GeneralSecurityException, DecoderException {


		final byte[] keyIdentifier = HexUtil.hexToBin("e8cc16a378c02f5da7093a1b3ab3e954d72c6a89df2c2ae27d2aecfb74aa9f313d4420c8611db21115fd6772d6d60840ae1a483f46f304b815735c96d1bb2061f6b78c7f9ae00612bc7050cd128e2f4d2cd3da1feef6a8a119e1f70a0b6333bfd908cdb4462d9a9b9ceb1fbdf6098e7db004a53b9a1e191622679bcd309a3cdc");
		final byte[] plaintext = HexUtil.hexToBin(
				"9e43e368af8a2dbf70d741409635fbe5862a1a6c585e9ef5ab484ad791f2b9d9c41518621d7d2333e611654f96d7557df81a363c5b8c8c265ffd276c4133d26f77");

		final EcPoint derivedKey = new EcPoint(
				"7892348142520120309830021689182451538899681643380253052731876013894381857492896607950503735584301507086549064629103",
				"31880498303417655539831659118689116678766928212885195670536268414124904549506099795135840689116769015888568110325436");

		// Test PRF key derived as OPRF output
		HmacKeyDerivationFunction hkdf = EntropyExtractor.getKeyGenerator(keyIdentifier, derivedKey);
		System.out.println(HexUtil.binToHex(hkdf.getPrfKey()));
		Assert.assertEquals(
						"d48f52e2bc025a4eab1ae81a9bd28c88c805beb9ddecaffa79fec3318646a036bdbec365dfe1634abd6234988b7f54141f90c621d43372b14cd92f01f0f8b2dc",
						HexUtil.binToHex(hkdf.getPrfKey()));

		// Generate AES key
		final byte[] keyBytes = hkdf.createKey(AES_256_KEY, 32);
		System.out.println(HexUtil.binToHex(keyBytes));
		Assert.assertEquals(
				"85c60dd5e6adf660986577383ca7ae42de129a93ba26dce14bf0cc4653fcc3ea",
				HexUtil.binToHex(keyBytes));

		// Generate AES IV
		final byte[] ivBytes = hkdf.createKey(AES_GCM_IV, 12);
		System.out.println(HexUtil.binToHex(ivBytes));
		Assert.assertEquals(
				"72049d10f84ff28e055fdfa2",
				HexUtil.binToHex(ivBytes));

		// Create Cipher
		final Cipher cipher = getCipher(keyBytes, ivBytes);
		final byte[] cipherText = cipher.doFinal(plaintext);
		Assert.assertEquals(plaintext.length + ivBytes.length, cipherText.length);
		
		System.out.println(HexUtil.binToHex(cipherText));
		Assert.assertEquals(
				"159c9cf155d9106797025ec9f5b6b10e68decad490dffb4db0405fbea2ec81c7bf3a30fb8853de8a85c35f1156b028717ee88cfdceed385445bf02dcae6e8e9cbb7c3b95d623996cfd233f8649",
				HexUtil.binToHex(cipherText));
	}

	// Test Vector 07: curve secp521r1, short key id, encryption
	@Test
	public void testVector07() throws GeneralSecurityException, DecoderException {


		final byte[] keyIdentifier = HexUtil.hexToBin("72e922e9bd68e58d249f79a74394bc95637866f1ee378659d6eee506270662fc");
		final byte[] plaintext = HexUtil.hexToBin(
				"44d1db84ab4d588aa9b08d84fd8878fd9537f03888b3edc6f205cc971a3e50578dd6f9e9c666e22ece7ec6bb2d3a19911f23c587a08197fae75c978e46b9ba9654");

		final EcPoint derivedKey = new EcPoint(
				"4870623013441813145710086359281291603571623556543243272145985459834059014907819208295824572272501836735622098177262642925126679860118886886233621524972379058",
				"5479002887868853265862616263553297893091432930809453098607154859866756058604140302155203591542419300366613779845868598246037514587244024631341704153705888680");

		// Test PRF key derived as OPRF output
		HmacKeyDerivationFunction hkdf = EntropyExtractor.getKeyGenerator(keyIdentifier, derivedKey);
		System.out.println(HexUtil.binToHex(hkdf.getPrfKey()));
		Assert.assertEquals(
						"8d61b24eda5d19ba6062ea0c5f5d4f9af9f8149a3a21dcb04012f2a966db1844bc583bae768bfd1270efcd75feff3287be9a5a19b95ea3c1232d20cf5467eeb9",
						HexUtil.binToHex(hkdf.getPrfKey()));

		// Generate AES key
		final byte[] keyBytes = hkdf.createKey(AES_256_KEY, 32);
		System.out.println(HexUtil.binToHex(keyBytes));
		Assert.assertEquals(
				"2bd1774eac4121cf32f223ffd9693e007344290a43dd21e2f8a87b8dd41ec6f8",
				HexUtil.binToHex(keyBytes));

		// Generate AES IV
		final byte[] ivBytes = hkdf.createKey(AES_GCM_IV, 12);
		System.out.println(HexUtil.binToHex(ivBytes));
		Assert.assertEquals(
				"4cfb0bcff7237e32c7fb239f",
				HexUtil.binToHex(ivBytes));

		// Create Cipher
		final Cipher cipher = getCipher(keyBytes, ivBytes);
		final byte[] cipherText = cipher.doFinal(plaintext);
		Assert.assertEquals(plaintext.length + ivBytes.length, cipherText.length);
		
		System.out.println(HexUtil.binToHex(cipherText));
		Assert.assertEquals(
				"612a453d658d03caf9d70c86db6fe3c4600881c221252bdc1e81733b9ed28ef68c37a5b032241409266c951b6040b3fc28fef309b25a383c7ceca209c90627b449e25e16f0fd8afb0b052ac4e1",
				HexUtil.binToHex(cipherText));
	}

	// Test Vector 08: curve secp521r1, long key id, encryption
	@Test
	public void testVector08() throws GeneralSecurityException, DecoderException {


		final byte[] keyIdentifier = HexUtil.hexToBin("e7551bda0d652c3c7822934cb200e9c4c2aed4b34b754a2de72b57f830ccb969192b1f0efb5d8a30aa7b7d5eb89796a52051892bcc67aede9f76b07dbf4f73eafe140b7ef7bc25ddb5a322bcb591d4240c82c15be39eeaa42ea6e35ef714d29e84fededf80c2233789e1656c5231260c64184c595eb83b6116e115035d07dcdb");
		final byte[] plaintext = HexUtil.hexToBin(
				"3c2634e5b8d1388db66540dbd0f0e08c15d0ad92b2823219776e2b0d2e79e317b25699d88ff54a480225747fcd64d9da42d4963a81e512d153f84e65a95d8d3d90");

		final EcPoint derivedKey = new EcPoint(
				"5693037708746374419754171023723834520098954645462535632452746470437443621824514239093694051745159198530402505535992809514624203130792383521552214733005091645",
				"6106858091482203807096364100531524392879030755234504575108735144722358990883005329464660620005636036825917772858611006382047703210868188078390376936705579303");

		// Test PRF key derived as OPRF output
		HmacKeyDerivationFunction hkdf = EntropyExtractor.getKeyGenerator(keyIdentifier, derivedKey);
		System.out.println(HexUtil.binToHex(hkdf.getPrfKey()));
		Assert.assertEquals(
						"26a50c71d5c26d218a86650c98b4a4a177a7e6dc9334956ae412f15b555c8cfa65d0a36bd3459860dadde1134f39bebf482f7775008ff41f1416e0ef30ae58ea",
						HexUtil.binToHex(hkdf.getPrfKey()));

		// Generate AES key
		final byte[] keyBytes = hkdf.createKey(AES_256_KEY, 32);
		System.out.println(HexUtil.binToHex(keyBytes));
		Assert.assertEquals(
				"20de3f4ff9328965a7a08a1c254b010c2ab1c71f007f2f2a92f48b3581b988ff",
				HexUtil.binToHex(keyBytes));

		// Generate AES IV
		final byte[] ivBytes = hkdf.createKey(AES_GCM_IV, 12);
		System.out.println(HexUtil.binToHex(ivBytes));
		Assert.assertEquals(
				"929cf388b7a182d4fc0daf0a",
				HexUtil.binToHex(ivBytes));

		// Create Cipher
		final Cipher cipher = getCipher(keyBytes, ivBytes);
		final byte[] cipherText = cipher.doFinal(plaintext);
		Assert.assertEquals(plaintext.length + ivBytes.length, cipherText.length);
		
		System.out.println(HexUtil.binToHex(cipherText));
		Assert.assertEquals(
				"d681b51c99028d43417eca7bfd2363dc92bd1b9476525045b8e6d6ac6c81466ba071448debc24bab6741d9d88bb3e5100fcc76a001988c386ad4bfd6233a5052d2a1b647efe9d8d914beb92f36",
				HexUtil.binToHex(cipherText));
	}

}
