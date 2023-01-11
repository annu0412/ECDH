package com.montymobile.test.assignment;

import java.security.*;
import java.security.spec.*;
import javax.crypto.*;
import javax.crypto.spec.*;

/**
 * ECDH
 * 
 * @author AnuragSharma
 *
 */
public class ECDH {

	public static void main(String[] args) throws Exception {

		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

		// generate private key for Alice
		KeyPair aliceKeyPair = generateKeyPair();
		PrivateKey alicePrivateKey = aliceKeyPair.getPrivate();

		// generate public key for Bob
		KeyPair bobKeyPair = generateKeyPair();

		PublicKey bobPublicKey = bobKeyPair.getPublic();

		// Alice computes shared secret
		byte[] aliceSharedSecret = generateSharedSecret(alicePrivateKey, bobPublicKey);

		// Bob computes shared secret
		byte[] bobSharedSecret = generateSharedSecret(bobKeyPair.getPrivate(), aliceKeyPair.getPublic());

		// check if shared secrets are the same
		if (java.util.Arrays.equals(aliceSharedSecret, bobSharedSecret)) {
			System.out.println("Shared secrets are the same.");
		} else {
			System.out.println("Shared secrets are different.");
		}
	}

	/**
	 * Generate new key pair
	 * 
	 * @return Generated Key pair
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchProviderException
	 * @throws InvalidAlgorithmParameterException
	 */
	public static KeyPair generateKeyPair()
			throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("ECDH", "BC");
		ECGenParameterSpec ecSpec = new ECGenParameterSpec("secp256r1");
		keyGen.initialize(ecSpec, new SecureRandom());
		KeyPair keyPair = keyGen.generateKeyPair();
		return keyPair;
	}

	/**
	 * Generate Shared secret
	 * 
	 * @param privateKey
	 *            - Private key of the party
	 * @param publicKey
	 *            - Public key of the party
	 * @return Generated secret
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchProviderException
	 * @throws InvalidKeyException
	 */
	public static byte[] generateSharedSecret(Key privateKey, Key publicKey)
			throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException {
		KeyAgreement keyAgree = KeyAgreement.getInstance("ECDH", "BC");
		keyAgree.init(privateKey);
		keyAgree.doPhase(publicKey, true);
		return keyAgree.generateSecret();

	}
}
