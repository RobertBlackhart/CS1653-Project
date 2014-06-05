import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.security.*;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Scanner;

public abstract class Client
{
	/* protected keyword is like private but subclasses have access
	 * Socket and input/output streams
	 */

	protected ObjectOutputStream output;
	protected ObjectInputStream input;
	Cipher encryptCipher, decryptCipher;
	protected Socket sock;
	protected SecretKey encryptionKey, signingKey;
	protected PublicKey publicKey;
	protected PrivateKey privateKey;
	protected BigInteger messageIndex;
	final byte[] ivBytes = new byte[]{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};

	public boolean connect(String username, String weakSecret, final String server, final int port)
	{
		System.out.println("attempting to connect");

		try
		{
			sock = new Socket();
			sock.connect(new InetSocketAddress(server, port));
			output = new ObjectOutputStream(sock.getOutputStream());
			input = new ObjectInputStream(sock.getInputStream());
			output.writeObject(username);

			//do DH exchange and agree on starting message index
			try
			{
				if(weakSecret != null) //group server connect
				{
					HashMap<String,SecretKey> secretKeys = DHKeyExchange.generateSecretKeyWithWeakSecret(username,weakSecret, input, output);
					if(secretKeys == null)
						throw new Exception("Unable to verify server");
					encryptionKey = secretKeys.get("encryptionKey");
					signingKey = secretKeys.get("signingKey");
				}
				else //file server connect
				{
					PublicKey fileServerPublicKey = (PublicKey) input.readObject(); //read in public key

					File savedKeys = new File("savedkeys.bin");
					ArrayList<PublicKey> knownKeys = new ArrayList<PublicKey>();
					if(savedKeys.exists())
					{
						ObjectInputStream in = new ObjectInputStream(new FileInputStream(savedKeys));
						knownKeys = (ArrayList<PublicKey>) in.readObject();
					}
					if(!knownKeys.contains(fileServerPublicKey)) //prompt the user to verify the key
					{
						MessageDigest sha = MessageDigest.getInstance("SHA-1");
						byte[] digest = sha.digest(fileServerPublicKey.getEncoded());
						System.out.println("RSA key fingerprint is " + getFingerprint(digest));
						System.out.println("Please verify this is correct by contacting the file server owner.");
						System.out.println("Do you want to add this key to your list of saved servers? (yes/no)");
						Scanner scanner = new Scanner(System.in);
						String answer = scanner.nextLine();
						if(answer.toLowerCase().equals("yes"))
						{
							knownKeys.add(fileServerPublicKey);
							savedKeys.delete();
							savedKeys.createNewFile();
							ObjectOutputStream out = new ObjectOutputStream(new FileOutputStream(savedKeys));
							out.writeObject(knownKeys);
							out.flush();
							out.close();
							output.writeObject("yes");
						}
						else
						{
							output.writeObject("no");
							System.out.println("Exiting");
							System.exit(0);
						}
					}
					else //accpet the key without prompt
						output.writeObject("yes");

					generateRSAKeypair();
					output.writeObject(publicKey);
					HashMap<String,SecretKey> secretKeys = DHKeyExchange.generateSecretKeySignedExchange(input, output, privateKey, fileServerPublicKey);
					if(secretKeys == null)
						throw new Exception("Unable to verify server");
					encryptionKey = secretKeys.get("encryptionKey");
					signingKey = secretKeys.get("signingKey");
				}

				encryptCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
				decryptCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
				MessageDigest sha = MessageDigest.getInstance("SHA-1");
				byte[] key = sha.digest(encryptionKey.getEncoded());
				key = Arrays.copyOf(key, 16); // use only first 128 bit

				SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");
				encryptCipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, new IvParameterSpec(ivBytes));
				decryptCipher.init(Cipher.DECRYPT_MODE, secretKeySpec, new IvParameterSpec(ivBytes));

				BigInteger R = new BigInteger(128,new SecureRandom());
				output.writeObject(encryptCipher.doFinal(R.toByteArray()));
				BigInteger start = new BigInteger(decryptCipher.doFinal((byte[])input.readObject()));
				if(start.compareTo(R) < 0)
					throw new Exception("Invalid message index from server");
				else
					messageIndex = start.add(BigInteger.ONE);
			}
			catch(Exception ex)
			{
				System.out.println("Failed to connect: " + ex.getMessage());
				//if anything fails, we are not connected
				sock = null;
				return false;
			}
		}
		catch(IOException ex)
		{
			return false;
		}

		return true;
	}

	private void generateRSAKeypair()
	{
		try
		{
			KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
			keyGen.initialize(1024);
			KeyPair keys = keyGen.generateKeyPair();
			publicKey = keys.getPublic();
			privateKey = keys.getPrivate();
		}
		catch(Exception e)
		{
			e.printStackTrace();
		}
	}

	public boolean isConnected()
	{
		//sock.isConnected() will return true if the socket has EVER been connected
		//won't detect when the other end hangs up
		if(sock == null || !sock.isConnected())
		{
			return false;
		}
		else
		{
			return true;
		}
	}

	public void disconnect()
	{
		if(isConnected())
		{
			try
			{
				Envelope message = new Envelope("DISCONNECT");
				message.addObject(messageIndex);
				output.writeObject(encryptCipher.doFinal(message.getBytes()));
				sock.close();
				sock = null;
			}
			catch(Exception e)
			{
				System.err.println("Error: " + e.getMessage());
				e.printStackTrace(System.err);
			}
		}
	}

	private static String getFingerprint(byte[] bytes)
	{
		StringBuilder string = new StringBuilder();
		for(byte b : bytes)
		{
			String hexString = Integer.toHexString(0x00FF & b);
			string.append(hexString.length() == 1 ? "0" + hexString : hexString);
			string.append(":");
		}
		String rendered = string.toString();
		return rendered.substring(0,rendered.length()-1); //cut off last :
	}
}
