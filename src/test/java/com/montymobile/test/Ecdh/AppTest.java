package com.montymobile.test.Ecdh;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.util.Arrays;
import org.junit.Assert;
import org.junit.Test;

import com.montymobile.test.assignment.ECDH;

/**
 * Unit test for simple App.
 */
public class AppTest {
	{
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

	}

	/**
	 * Positive test
	 * 
	 */
	@Test
	public void test1_positiveTest() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException,
			NoSuchProviderException, InvalidKeyException {

		KeyPair keyPair1 = ECDH.generateKeyPair();

		KeyPair keyPair2 = ECDH.generateKeyPair();

		byte[] sharedSec1 = ECDH.generateSharedSecret(keyPair1.getPrivate(), keyPair2.getPublic());
		byte[] sharedSec2 = ECDH.generateSharedSecret(keyPair2.getPrivate(), keyPair1.getPublic());
		Assert.assertTrue(Arrays.equals(sharedSec1, sharedSec2));

	}

	/**
	 * Negative test
	 * @throws InvalidAlgorithmParameterException
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchProviderException
	 * @throws InvalidKeyException
	 */
	@Test
	public void test2_NegativeTest() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException,
			NoSuchProviderException, InvalidKeyException {

		KeyPair keyPair1 = ECDH.generateKeyPair();

		KeyPair keyPair2 = ECDH.generateKeyPair();

		KeyPair keyPair3 = ECDH.generateKeyPair();

		byte[] sharedSec1 = ECDH.generateSharedSecret(keyPair1.getPrivate(), keyPair2.getPublic());
		byte[] sharedSec2 = ECDH.generateSharedSecret(keyPair2.getPrivate(), keyPair3.getPublic());
		Assert.assertFalse(Arrays.equals(sharedSec1, sharedSec2));

	}
}
