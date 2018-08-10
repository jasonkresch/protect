/*
 * Copyright (c) IBM Corporation 2018. All Rights Reserved.
 * Project name: pross
 * This project is licensed under the MIT License, see LICENSE.
 */

package com.ibm.pross.common.util.crypto.ecc;

import org.junit.Assert;
import org.junit.Test;

import com.ibm.pross.common.util.crypto.kdf.HmacKeyDerivationFunction;

public class PointHasherTest {
	// Test Vector 09: (secp256r1, without client secret, key id with special
	// characters)
	@Test
	public void testVector09() {
		final PointHasher pointHasher = EcCurve.secp256r1.getPointHasher();
		EcPoint result = pointHasher.hashToCurve("これはテストです。 - 000");
		System.out.println("Test Vector Point: " + result);
		EcPoint expected = new EcPoint("8160756293490157937104077009852267937992106172572270634375298423831985947063",
				"104553581667911433399913073322205673437677128806540598101562998497852216837154");
		Assert.assertEquals(expected, result);
	}

	// Test Vector 10: (secp256r1, without client secret, key id as byte array
	// with very long value (over 100 bytes long))
	@Test
	public void testVector10() {
		// Generate random bytes
		final HmacKeyDerivationFunction hkdf = new HmacKeyDerivationFunction(HmacKeyDerivationFunction.HDFK_SHA512,
				new byte[0]);
		final byte[] inputBytes = hkdf.createKey(new byte[] { 0, 1, 2 }, 4096);

		final PointHasher pointHasher = EcCurve.secp256r1.getPointHasher();
		EcPoint result = pointHasher.hashToCurve(inputBytes);
		System.out.println("Test Vector Point: " + result);
		EcPoint expected = new EcPoint(
				"11039227954369684306746808884983317744276427225717600742461221298580750897006",
				"36016287457661471590508534387087399559446866035089773400149980103149827256280");
		Assert.assertEquals(expected, result);
	}

	// Test Vector 11: (secp256r1, with client secret, key id with special
	// characters)
	@Test
	public void testVector11() {
		final PointHasher pointHasher = EcCurve.secp256r1.getPointHasher();
		EcPoint result = pointHasher.hashToCurve("Սա թեստ է. - 000", new byte[] { 0, 1, 2, 3, 4, 5 });
		System.out.println("Test Vector Point: " + result);
		EcPoint expected = new EcPoint("72490600699767087869583650510771030578645071394694463565852904957146141891302",
				"115427375323384429237846670251500697595221555568950232082786903024043133355824");
		Assert.assertEquals(expected, result);
	}

	// Test Vector 12: (secp256r1, with client secret, key id as byte array with
	// very long value (over 100 bytes long))
	@Test
	public void testVector12() {
		// Generate random bytes
		final HmacKeyDerivationFunction hkdf = new HmacKeyDerivationFunction(HmacKeyDerivationFunction.HDFK_SHA512,
				new byte[1]);
		final byte[] inputBytes = hkdf.createKey(new byte[] { 2, 1, 0 }, 1075);

		final PointHasher pointHasher = EcCurve.secp256r1.getPointHasher();
		EcPoint result = pointHasher.hashToCurve(inputBytes, new byte[] { 10, 20, 30, 40, 50, 60, 70, 80 });
		System.out.println("Test Vector Point: " + result);
		EcPoint expected = new EcPoint("66365836320285488201265404165327446318859770471693408088597597102028710810309",
				"54949973045157236811448482808474860099731881620747065797028338410773406695554");
		Assert.assertEquals(expected, result);
	}

	// Test Vector 13: (secp256r1, with client secret, key id as zero length
	// byte array)
	@Test
	public void testVector13() {
		final PointHasher pointHasher = EcCurve.secp256r1.getPointHasher();
		EcPoint result = pointHasher.hashToCurve(new byte[0],
				new byte[] { 11, 22, 33, 44, 55, 66, 77, 88, 99, (byte) 0xAA });
		System.out.println("Test Vector Point: " + result);
		EcPoint expected = new EcPoint("7896639666179850600089770859633179318609745119740988802865031172234535885203",
				"40879632738687313280027362084246141692225199417980157740680594485795347875719");
		Assert.assertEquals(expected, result);
	}

	// Test Vector 14: (secp256r1, with client secret, key id as zero length
	// string)
	@Test
	public void testVector14() {
		final PointHasher pointHasher = EcCurve.secp256r1.getPointHasher();
		EcPoint result = pointHasher.hashToCurve("", new byte[] { 55, 55, 55, 55 });
		System.out.println("Test Vector Point: " + result);
		EcPoint expected = new EcPoint("34502842255001386387717095630373952365171530842726321314435873455709509056582",
				"71762966156352830344031618230197349036842051841694967722902111008842315621472");
		Assert.assertEquals(expected, result);
	}

	// Test Vector 15: (secp256r1, with client secret, key id as string "\0\0" –
	// two null characters)
	@Test
	public void testVector15() {
		final PointHasher pointHasher = EcCurve.secp256r1.getPointHasher();
		EcPoint result = pointHasher.hashToCurve("\0\0", new byte[] { 33 });
		System.out.println("Test Vector Point: " + result);
		EcPoint expected = new EcPoint("78791362913061142052283840101212832644239940934329270745075067138172117066082",
				"89581367401324877302121736380669688982612182875359444403317843879794951201983");
		Assert.assertEquals(expected, result);
	}

	// Test Vector 16: (secp256r1, with client secret, with key id, with 10,000
	// iterations of feedback permuting id and client bytes, checking final
	// result
	@Test
	public void testVector16() {
		final PointHasher pointHasher = EcCurve.secp256r1.getPointHasher();
		EcPoint result = pointHasher.hashToCurve("many iterations", new byte[] { 33 });

		for (int i = 0; i < 1_000; i++) {
			result = pointHasher.hashToCurve(result.getX().toByteArray(), result.getY().toByteArray());
			result = pointHasher.hashToCurve(result.getX().toString(), result.getY().toByteArray());
			result = pointHasher.hashToCurve(result.getX().toByteArray());
		}

		System.out.println("Test Vector Point: " + result);
		EcPoint expected = new EcPoint("87422140857139152667482592327937017315424432789441218250385690011486939036655",
				"39213631762705631836491143911725276649478330733393183960895846941046859976276");
		Assert.assertEquals(expected, result);
	}

	// Test Vector 17: (secp384r1, without client secret, key id with special
	// characters)
	@Test
	public void testVector17() {
		final PointHasher pointHasher = EcCurve.secp384r1.getPointHasher();
		EcPoint result = pointHasher.hashToCurve("これはテストです。 - 000");
		System.out.println("Test Vector Point: " + result);
		EcPoint expected = new EcPoint(
				"36356043485975346333457105717872391079632675916903472784774406677408541999903430234528771273019361942677940785173250",
				"34933125769622752831715865749088756227806308117555136100099018695833338047445739177872612859076884778019082142515565");
		Assert.assertEquals(expected, result);
	}

	// Test Vector 18: (secp384r1, without client secret, key id as byte array
	// with very long value (over 100 bytes long))
	@Test
	public void testVector18() {
		// Generate random bytes
		final HmacKeyDerivationFunction hkdf = new HmacKeyDerivationFunction(HmacKeyDerivationFunction.HDFK_SHA512,
				new byte[0]);
		final byte[] inputBytes = hkdf.createKey(new byte[] { 0, 1, 2 }, 4096);

		final PointHasher pointHasher = EcCurve.secp384r1.getPointHasher();
		EcPoint result = pointHasher.hashToCurve(inputBytes);
		System.out.println("Test Vector Point: " + result);
		EcPoint expected = new EcPoint(
				"13574875865813460249138662550698218803344127707850688963302044462592953166902667130065024915236575599853564091775290",
				"8450942680331909847902806980881161384447495168235739504502265930417469323805437311384304845899387819654924561237326");
		Assert.assertEquals(expected, result);
	}

	// Test Vector 19: (secp384r1, with client secret, key id with special
	// characters)
	@Test
	public void testVector19() {
		final PointHasher pointHasher = EcCurve.secp384r1.getPointHasher();
		EcPoint result = pointHasher.hashToCurve("Սա թեստ է. - 000", new byte[] { 0, 1, 2, 3, 4, 5 });
		System.out.println("Test Vector Point: " + result);
		EcPoint expected = new EcPoint(
				"22487163814000423773169706831448700997907697629306166077906276830638169697648654713275967733265791715484990753586280",
				"19387101273150539423818000202675984505009666022439228161156252666637772402283480398587366905127744873212369175027417");
		Assert.assertEquals(expected, result);
	}

	// Test Vector 20: (secp384r1, with client secret, key id as byte array with
	// very long value (over 100 bytes long))
	@Test
	public void testVector20() {
		// Generate random bytes
		final HmacKeyDerivationFunction hkdf = new HmacKeyDerivationFunction(HmacKeyDerivationFunction.HDFK_SHA512,
				new byte[1]);
		final byte[] inputBytes = hkdf.createKey(new byte[] { 2, 1, 0 }, 1075);

		final PointHasher pointHasher = EcCurve.secp384r1.getPointHasher();
		EcPoint result = pointHasher.hashToCurve(inputBytes, new byte[] { 10, 20, 30, 40, 50, 60, 70, 80 });
		System.out.println("Test Vector Point: " + result);
		EcPoint expected = new EcPoint(
				"18472326435799297199540918736210996374391000234188481509606224682026951428999829341873918979570524072852674044990837",
				"36015316563939518710695405243428908234052604837304134581248705816046899659694854481403243019452630718198370632515308");
		Assert.assertEquals(expected, result);
	}

	// Test Vector 21: (secp384r1, with client secret, key id as zero length
	// byte array)
	@Test
	public void testVector21() {
		final PointHasher pointHasher = EcCurve.secp384r1.getPointHasher();
		EcPoint result = pointHasher.hashToCurve(new byte[0],
				new byte[] { 11, 22, 33, 44, 55, 66, 77, 88, 99, (byte) 0xAA });
		System.out.println("Test Vector Point: " + result);
		EcPoint expected = new EcPoint(
				"19678831572965461857319490557829054008541329087889191596444736987251863226939871193188895839870686922218697274076622",
				"25741313484764229689392258125844960485361555829784474310754394903809496966038394823627454873649644958138834294214380");
		Assert.assertEquals(expected, result);
	}

	// Test Vector 22: (secp384r1, with client secret, key id as zero length
	// string)
	@Test
	public void testVector22() {
		final PointHasher pointHasher = EcCurve.secp384r1.getPointHasher();
		EcPoint result = pointHasher.hashToCurve("", new byte[] { 55, 55, 55, 55 });
		System.out.println("Test Vector Point: " + result);
		EcPoint expected = new EcPoint(
				"30979847147089899804674484634121527441953597483460650913401405435994181033789098469374214407500372861531098569731033",
				"23209681125442532727693763079951245692918354043105000022879341569657086310677031495237643308427059957930290208439626");
		Assert.assertEquals(expected, result);
	}

	// Test Vector 23: (secp384r1, with
	// client secret, key id as string "\0\0" – two null characters)
	@Test
	public void testVector23() {
		final PointHasher pointHasher = EcCurve.secp384r1.getPointHasher();
		EcPoint result = pointHasher.hashToCurve("\0\0", new byte[] { 33 });
		System.out.println("Test Vector Point: " + result);
		EcPoint expected = new EcPoint(
				"7763899370647065123955729006036253081645787623908879312559181294297578406204237957665116013840670160173435129662380",
				"11522349853850539109355601163427672755953290301757734891652328681130763454784914454191453662004670127408616122173342");
		Assert.assertEquals(expected, result);
	}

	// Test Vector 24: (secp384r1, with client secret, with key id, with 10,000
	// iterations of feedback permuting id and client bytes, checking final
	// result
	@Test
	public void testVector24() {
		final PointHasher pointHasher = EcCurve.secp384r1.getPointHasher();
		EcPoint result = pointHasher.hashToCurve("many iterations", new byte[] { 33 });

		for (int i = 0; i < 1_000; i++) {
			result = pointHasher.hashToCurve(result.getX().toByteArray(), result.getY().toByteArray());
			result = pointHasher.hashToCurve(result.getX().toString(), result.getY().toByteArray());
			result = pointHasher.hashToCurve(result.getX().toByteArray());
		}

		System.out.println("Test Vector Point: " + result);
		EcPoint expected = new EcPoint("35749280027787464948199176615145888607867516695213093596318305537547694698572850209810264295342144304741953445481973",
				"13376522774360324209000742841135897608120797012635166706190778783497772844269650413633525065870253332962141494442518");
		Assert.assertEquals(expected, result);
	}

	// Test Vector 25: (secp521r1, without client secret, key id with special
	// characters)
	@Test
	public void testVector25() {
		final PointHasher pointHasher = EcCurve.secp521r1.getPointHasher();
		EcPoint result = pointHasher.hashToCurve("これはテストです。 - 000");
		System.out.println("Test Vector Point: " + result);
		EcPoint expected = new EcPoint(
				"6191487222210564448772335211457210938516615085452855919729018411388007357277038008631492258793965506434674986351250040172893888274818983335827690153293498549",
				"478603636026424436465883070954921918993418934325897789584843266322025766810157042383568765203272650895857789366177202156865970683507978863407136199977206958");
		Assert.assertEquals(expected, result);
	}

	// Test Vector 26: (secp521r1, without client secret, key id as byte array
	// with very long value (over 100 bytes long))
	@Test
	public void testVector26() {
		// Generate random bytes
		final HmacKeyDerivationFunction hkdf = new HmacKeyDerivationFunction(HmacKeyDerivationFunction.HDFK_SHA512,
				new byte[0]);
		final byte[] inputBytes = hkdf.createKey(new byte[] { 0, 1, 2 }, 4096);

		final PointHasher pointHasher = EcCurve.secp521r1.getPointHasher();
		EcPoint result = pointHasher.hashToCurve(inputBytes);
		System.out.println("Test Vector Point: " + result);
		EcPoint expected = new EcPoint(
				"6637700257754665590564945745229128177714476830594010797342647503072236721750820446208564359250646631193691178633006744780460946014010326706138578765770702899",
				"4753983695885564962207201996196774516739708536137737835837298240909635858516954081526626337766420596488749975714290697655337755136291881229840237401694181151");
		Assert.assertEquals(expected, result);
	}

	// Test Vector 27: (secp521r1, with client secret, key id with special
	// characters)
	@Test
	public void testVector27() {
		final PointHasher pointHasher = EcCurve.secp521r1.getPointHasher();
		EcPoint result = pointHasher.hashToCurve("Սա թեստ է. - 000", new byte[] { 0, 1, 2, 3, 4, 5 });
		System.out.println("Test Vector Point: " + result);
		EcPoint expected = new EcPoint(
				"3038724042067910174032905595981199785029274346863580235196526608198675734224149134578886457390312083651470577489736345089219376240921319238564573086828369113",
				"3696208761264702993813136138756536368367659195248760215625340194968540385094321442895196682250835181298162136889416123496767420563229832842495382539036307177");
		Assert.assertEquals(expected, result);
	}

	// Test Vector 28: (secp521r1, with
	// client secret, key id as byte array with very long value (over 100 bytes
	// long))
	@Test
	public void testVector28() {
		// Generate random bytes
		final HmacKeyDerivationFunction hkdf = new HmacKeyDerivationFunction(HmacKeyDerivationFunction.HDFK_SHA512,
				new byte[1]);
		final byte[] inputBytes = hkdf.createKey(new byte[] { 2, 1, 0 }, 1075);

		final PointHasher pointHasher = EcCurve.secp521r1.getPointHasher();
		EcPoint result = pointHasher.hashToCurve(inputBytes, new byte[] { 10, 20, 30, 40, 50, 60, 70, 80 });
		System.out.println("Test Vector Point: " + result);
		EcPoint expected = new EcPoint(
				"752055761245976537245044877676755997022919211027260710282882415241566001863894953680799475023491105322824994228470455475313634832621653988721696243844728976",
				"1159323805589781473603815826431672037008924535683590633169695454490399397142588387356815249385467632128048115676395726606677366644899583071269210415871568490");
		Assert.assertEquals(expected, result);
	}

	// Test Vector 29: (secp521r1, with
	// client secret, key id as zero length byte array)
	@Test
	public void testVector29() {
		final PointHasher pointHasher = EcCurve.secp521r1.getPointHasher();
		EcPoint result = pointHasher.hashToCurve(new byte[0],
				new byte[] { 11, 22, 33, 44, 55, 66, 77, 88, 99, (byte) 0xAA });
		System.out.println("Test Vector Point: " + result);
		EcPoint expected = new EcPoint(
				"1783851076003529767035155315461919894050514202067112434019551095180471036058065098640476136691168578498771593982716016777404893550430714109947925297515046993",
				"914146046462392723974102965482403002456448511058070082650968911527023915487284262077530946655123456158012477081002877719281121732785866245804306513523772712");
		Assert.assertEquals(expected, result);
	}

	// Test Vector 30: (secp521r1, with
	// client secret, key id as zero length string)
	@Test
	public void testVector30() {
		final PointHasher pointHasher = EcCurve.secp521r1.getPointHasher();
		EcPoint result = pointHasher.hashToCurve("", new byte[] { 55, 55, 55, 55 });
		System.out.println("Test Vector Point: " + result);
		EcPoint expected = new EcPoint(
				"2768349715079449444231566354465020534634915115767115468302150473018588917518015402422449264716777593497296537839044872846608596157327621194172704431949602173",
				"1721075987500708626593431035845099406033376640406833904074563079331527369533486419760886310715297738198901920467665231428286533003113019266397765708681873858");
		Assert.assertEquals(expected, result);
	}

	// Test Vector 31: (secp521r1, with
	// client secret, key id as string "\0\0" – two null characters)
	@Test
	public void testVector31() {
		final PointHasher pointHasher = EcCurve.secp521r1.getPointHasher();
		EcPoint result = pointHasher.hashToCurve("\0\0", new byte[] { 33 });
		System.out.println("Test Vector Point: " + result);
		EcPoint expected = new EcPoint(
				"4074929226949852656169452358205020193456244541438429028817020605571709507349451195959768710815992652116057131452783490570662886374283043317162034010905093798",
				"4721194906272974467264032148793157563036519040858266237014143723409811371938325004765737325737938490155703567917839865487269241326144177827417689953207050916");
		Assert.assertEquals(expected, result);
	}

	// Test Vector 32: (secp521r1, with client secret, with key id, with 10,000
	// iterations of feedback permuting id and client bytes, checking final
	// result
	@Test
	public void testVector32() {
		final PointHasher pointHasher = EcCurve.secp521r1.getPointHasher();
		EcPoint result = pointHasher.hashToCurve("many iterations", new byte[] { 33 });

		for (int i = 0; i < 1_000; i++) {
			result = pointHasher.hashToCurve(result.getX().toByteArray(), result.getY().toByteArray());
			result = pointHasher.hashToCurve(result.getX().toString(), result.getY().toByteArray());
			result = pointHasher.hashToCurve(result.getX().toByteArray());
		}

		System.out.println("Test Vector Point: " + result);
		EcPoint expected = new EcPoint("5098804692815653337908975274613466449121576925807854019577825838305228038069444239854579192524292835132933570541365313574917792339427478399000370088506672626",
				"3590247739091575686464441778812822661795595481131536598683858432503556681200256539494591014014610887143710202425185528051617626214302520048804792230208929880");
		Assert.assertEquals(expected, result);
	}



}
