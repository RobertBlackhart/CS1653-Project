import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.KeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;

public class DHKeyExchange
{
	static final String P = "B10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C69A6A9DCA52D23B616073E28675A23D189838EF1E2EE652C013ECB4AEA906112324975C3CD49B83BFACCBDD7D90C4BD7098488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708DF1FB2BC2E4A4371";
	static final String G = "A4D1CBD5C3FD34126765A442EFB99905F8104DD258AC507FD6406CFF14266D31266FEA1E5C41564B777E690F5504F213160217B4B01B886A5E91547F9E2749F4D7FBD7D3B9A92EE1909D0D2263F80A76A6A24C087A091F531DBF0A0169B6A28AD662A4D18E73AFA32D779D5918D08BC8858F4DCEF97C2A24855E6EEB22B3B2E5";
	static SecureRandom random = new SecureRandom();

	public static HashMap<String,SecretKey> generateSecretKeyWithWeakSecret(String username, String weakSecret, ObjectInputStream input, ObjectOutputStream output) throws Exception
	{
		Security.addProvider(new BouncyCastleProvider());

		KeyPairGenerator generator = KeyPairGenerator.getInstance("DH");

		//a
		DHParameterSpec dhParameterSpec = new DHParameterSpec(new BigInteger(P, 16), new BigInteger(G, 16), 1024); //1024bit for the private key
		generator.initialize(dhParameterSpec);
		KeyPair encryptionKeyPair = generator.generateKeyPair();

		//a'
		dhParameterSpec = new DHParameterSpec(new BigInteger(P, 16), new BigInteger(G, 16), 1024); //1024bit for the private key
		generator.initialize(dhParameterSpec);
		KeyPair signingKeyPair = generator.generateKeyPair();

		// Get the generated public and private keys
		PrivateKey encryptionPrivateKey = encryptionKeyPair.getPrivate();
		PublicKey encryptionPublicKey = encryptionKeyPair.getPublic();
		PrivateKey signingPrivateKey = signingKeyPair.getPrivate();
		PublicKey signingPublicKey = signingKeyPair.getPublic();

		//create secret key from weak secret
		byte[] salt = username.getBytes();
		SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
		KeySpec keySpec = new PBEKeySpec(weakSecret.toCharArray(),salt,4000,128);
		SecretKey secretKey = keyFactory.generateSecret(keySpec);
		Key key = new SecretKeySpec(secretKey.getEncoded(),"AES");

		//encrypt public key
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		cipher.init(Cipher.ENCRYPT_MODE, key);
		byte[] encryptionPublicKeyBytes = cipher.doFinal(encryptionPublicKey.getEncoded());
		byte[] signingPublicKeyBytes = cipher.doFinal(signingPublicKey.getEncoded());

		//generate random challenge
		int randomChallenge = random.nextInt();

		// Send the encrypted public key bytes to the other party...
		Envelope envelope = new Envelope("PublicKey");
		envelope.addObject(cipher.getIV());
		envelope.addObject(encryptionPublicKeyBytes);
		envelope.addObject(signingPublicKeyBytes);
		envelope.addObject(randomChallenge);
		output.writeObject(envelope);

		// Retrieve the public key bytes of the other party
		envelope = (Envelope) input.readObject();
		byte[] iv = (byte[]) envelope.getObjContents().get(0);
		encryptionPublicKeyBytes = (byte[]) envelope.getObjContents().get(1);
		signingPublicKeyBytes = (byte[]) envelope.getObjContents().get(2);
		int challenge = (Integer) envelope.getObjContents().get(3);

		//decrypt public key
		cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
		encryptionPublicKeyBytes = cipher.doFinal(encryptionPublicKeyBytes);
		signingPublicKeyBytes = cipher.doFinal(signingPublicKeyBytes);

		// Convert the public key bytes into a PublicKey object
		X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(encryptionPublicKeyBytes);
		KeyFactory kf = KeyFactory.getInstance("DH");
		encryptionPublicKey = kf.generatePublic(x509KeySpec);

		x509KeySpec = new X509EncodedKeySpec(signingPublicKeyBytes);
		kf = KeyFactory.getInstance("DH");
		signingPublicKey = kf.generatePublic(x509KeySpec);

		// Prepare to generate the secret key with the private key and public key of the other party
		KeyAgreement keyAgreement = KeyAgreement.getInstance("DH");
		keyAgreement.init(encryptionPrivateKey);
		keyAgreement.doPhase(encryptionPublicKey, true);
		SecretKey encryptionSecret = keyAgreement.generateSecret("AES");

		keyAgreement = KeyAgreement.getInstance("DH");
		keyAgreement.init(signingPrivateKey);
		keyAgreement.doPhase(signingPublicKey, true);
		SecretKey signingSecret = keyAgreement.generateSecret("AES");

		//send back the random challenge encrypted with the secret key
		output.writeObject(challenge);

		int gotBack = (Integer) input.readObject();
		//receive challenge back and verify
		if(randomChallenge == gotBack)
		{
			HashMap<String,SecretKey> secretKeys = new HashMap<String, SecretKey>();
			secretKeys.put("encryptionKey",encryptionSecret);
			secretKeys.put("signingKey",signingSecret);
			return secretKeys;
		}
		else
			return null;
	}

	public static HashMap<String,SecretKey> generateSecretKeySignedExchange(ObjectInputStream input, ObjectOutputStream output, PrivateKey myPrivate, PublicKey othersPublic) throws Exception
	{
		Security.addProvider(new BouncyCastleProvider());

		KeyPairGenerator generator = KeyPairGenerator.getInstance("DH");

		//a
		DHParameterSpec dhParameterSpec = new DHParameterSpec(new BigInteger(P, 16), new BigInteger(G, 16), 1024); //1024bit for the private key
		generator.initialize(dhParameterSpec);
		KeyPair encryptionKeyPair = generator.generateKeyPair();

		//a'
		dhParameterSpec = new DHParameterSpec(new BigInteger(P, 16), new BigInteger(G, 16), 1024); //1024bit for the private key
		generator.initialize(dhParameterSpec);
		KeyPair signingKeyPair = generator.generateKeyPair();

		// Get the generated public and private keys
		PrivateKey encryptionPrivateKey = encryptionKeyPair.getPrivate();
		PublicKey encryptionPublicKey = encryptionKeyPair.getPublic();
		PrivateKey signingPrivateKey = signingKeyPair.getPrivate();
		PublicKey signingPublicKey = signingKeyPair.getPublic();

		// Send the public keys to the other party...
		Envelope envelope = new Envelope("PublicKeys");
		envelope.addObject(encryptionPublicKey);
		envelope.addObject(signingPublicKey);
		output.writeObject(envelope);

		Signature signature = Signature.getInstance("SHA1withRSA");
		signature.initSign(myPrivate);
		signature.update(envelope.getBytes());
		byte[] sig = signature.sign();
		output.writeObject(sig);

		// Retrieve the public keys of the other party
		envelope = (Envelope) input.readObject();
		encryptionPublicKey = (PublicKey) envelope.getObjContents().get(0);
		signingPublicKey = (PublicKey) envelope.getObjContents().get(1);

		sig = (byte[]) input.readObject();

		signature.initVerify(othersPublic);
		signature.update(envelope.getBytes());
		if(!signature.verify(sig))
		{
			System.out.println("Could not verify signature");
			return null;
		}

		// Convert the public key bytes into a PublicKey object
		X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(encryptionPublicKey.getEncoded());
		KeyFactory kf = KeyFactory.getInstance("DH");
		encryptionPublicKey = kf.generatePublic(x509KeySpec);

		x509KeySpec = new X509EncodedKeySpec(signingPublicKey.getEncoded());
		kf = KeyFactory.getInstance("DH");
		signingPublicKey = kf.generatePublic(x509KeySpec);

		// Prepare to generate the secret key with the private key and public key of the other party
		KeyAgreement keyAgreement = KeyAgreement.getInstance("DH");
		keyAgreement.init(encryptionPrivateKey);
		keyAgreement.doPhase(encryptionPublicKey, true);
		SecretKey encryptionSecret = keyAgreement.generateSecret("AES");

		keyAgreement.init(signingPrivateKey);
		keyAgreement.doPhase(signingPublicKey, true);
		SecretKey signingSecret = keyAgreement.generateSecret("AES");

		HashMap<String,SecretKey> secretKeys = new HashMap<String, SecretKey>();
		secretKeys.put("encryptionKey",encryptionSecret);
		secretKeys.put("signingKey",signingSecret);
		return secretKeys;
	}

	private static String bytes2String(byte[] bytes)
	{
		StringBuilder string = new StringBuilder();
		for(byte b : bytes)
		{
			String hexString = Integer.toHexString(0x00FF & b);
			string.append(hexString.length() == 1 ? "0" + hexString : hexString);
		}
		return string.toString();
	}
}