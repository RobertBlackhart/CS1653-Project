import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.SecureRandom;

public abstract class Server
{
	protected int port;
	public String name;
	static SecureRandom random = new SecureRandom();

	abstract void start();

	public Server(int _SERVER_PORT, String _serverName)
	{
		port = _SERVER_PORT;
		name = _serverName;
	}

	public Envelope encrypt(Envelope envelope) throws Exception
	{
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
		keyGenerator.init(128, random);
		SecretKey key = keyGenerator.generateKey();
		cipher.init(Cipher.ENCRYPT_MODE, key);

		byte[] cipherText = cipher.doFinal(envelope.getBytes());
		byte[] iv = cipher.getIV();

		Envelope returnEnvelope = new Envelope("Encrypted");
		returnEnvelope.addObject(cipherText);
		returnEnvelope.addObject(iv);
		return returnEnvelope;
	}

	public int getPort()
	{
		return port;
	}

	public String getName()
	{
		return name;
	}
}
