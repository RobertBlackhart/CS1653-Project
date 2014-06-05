/* FileClient provides all the client functionality regarding the file server */

import javax.crypto.Mac;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.List;

public class FileClient extends Client implements FileClientInterface
{
	private byte[] getHMAC(Envelope envelope, boolean removeHMAC) throws NoSuchAlgorithmException, InvalidKeyException
	{
		//if last object in envelope is an hmac, remove it before computing
		if(removeHMAC)
			envelope.getObjContents().remove(envelope.getObjContents().size()-1);

		Mac mac = Mac.getInstance("HmacSHA1");
		mac.init(signingKey);
		byte[] result = mac.doFinal(envelope.getBytes());
		return result;
	}

	//checks that the messageIndex is correct and the HMAC is valid
	private boolean validateMessage(Envelope envelope) throws NoSuchAlgorithmException, InvalidKeyException
	{
		//compare messageIndex
		if(((BigInteger) envelope.getObjContents().get(0)).add(BigInteger.ONE).compareTo(messageIndex) > 0)
			messageIndex = ((BigInteger) envelope.getObjContents().get(0)).add(BigInteger.ONE);
		else
			return false;

		//check if result is equal to the last object in the envelope (the sent hmac)
		if(envelope.getObjContents().get(envelope.getObjContents().size()-1).equals(getHMAC(envelope,true)))
			return false;

		return true;
	}

	public boolean delete(String filename, UserToken token)
	{
		String remotePath;
		if(filename.charAt(0) == '/')
		{
			remotePath = filename.substring(1);
		}
		else
		{
			remotePath = filename;
		}

		try
		{
			Envelope env = new Envelope("DELETEF"); //Success
			env.addObject(messageIndex);
			env.addObject(remotePath);
			env.addObject(token);
			env.addObject(getHMAC(env,false));
			output.writeObject(encryptCipher.doFinal(env.getBytes()));

			env = Envelope.fromBytes(decryptCipher.doFinal((byte[]) input.readObject()));

			if(validateMessage(env) && env.getMessage().compareTo("OK") == 0)
			{
				System.out.printf("File %s deleted successfully\n", filename);
			}
			else
			{
				System.out.printf("Error deleting file %s (%s)\n", filename, env.getMessage());
				return false;
			}
		}
		catch(Exception ex)
		{
			System.out.println("Error: " + ex.getMessage());
			return false;
		}

		return true;
	}

	public boolean download(String sourceFile, String destFile, UserToken token)
	{
		if(sourceFile.charAt(0) == '/')
		{
			sourceFile = sourceFile.substring(1);
		}

		File file = new File(destFile);
		try
		{
			if(!file.exists())
			{
				file.createNewFile();
				FileOutputStream fos = new FileOutputStream(file);

				Envelope env = new Envelope("DOWNLOADF"); //Success
				env.addObject(messageIndex);
				env.addObject(sourceFile);
				env.addObject(token);
				env.addObject(getHMAC(env,false));
				output.writeObject(encryptCipher.doFinal(env.getBytes()));

				env = Envelope.fromBytes(decryptCipher.doFinal((byte[]) input.readObject()));

				while(validateMessage(env) && env.getMessage().compareTo("CHUNK") == 0)
				{
					fos.write((byte[]) env.getObjContents().get(1), 0, (Integer) env.getObjContents().get(2));
					System.out.printf(".");
					env = new Envelope("DOWNLOADF"); //Success
					env.addObject(messageIndex);
					env.addObject(getHMAC(env, false));
					output.writeObject(encryptCipher.doFinal(env.getBytes()));
					env = Envelope.fromBytes(decryptCipher.doFinal((byte[]) input.readObject()));
				}
				fos.close();

				if(env.getMessage().compareTo("EOF") == 0)
				{
					fos.close();
					System.out.printf("\nTransfer successful file %s\n", sourceFile);
					env = new Envelope("OK"); //Success
					env.addObject(messageIndex);
					env.addObject(getHMAC(env,false));
					output.writeObject(encryptCipher.doFinal(env.getBytes()));
				}
				else
				{
					System.out.printf("Error reading file %s (%s)\n", sourceFile, env.getMessage());
					file.delete();
					return false;
				}
			}

			else
			{
			
				System.out.printf("File doesnt exist/nError couldn't create file %s\n", destFile);
				return false;
			}
		}
		catch(Exception e1)
		{
			e1.printStackTrace();
			System.out.printf("Error couldn't create file %s\n", destFile);
			return false;
		}
		return true;
	}

	@SuppressWarnings("unchecked")
	public List<String> listFiles(UserToken token)
	{
		try
		{
			Envelope message = null, e = null;
			//Tell the server to return the member list
			message = new Envelope("LFILES");
			message.addObject(messageIndex);
			message.addObject(token); //Add requester's token
			message.addObject(getHMAC(message,false));
			output.writeObject(encryptCipher.doFinal(message.getBytes()));

			e = Envelope.fromBytes(decryptCipher.doFinal((byte[]) input.readObject()));

			//If server indicates success, return the member list
			if(validateMessage(e) && e.getMessage().equals("OK"))
			{
				return (List<String>) e.getObjContents().get(1); //This cast creates compiler warnings. Sorry.
			}

			return null;

		}
		catch(Exception e)
		{
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
			return null;
		}
	}

	public boolean upload(String sourceFile, String destFile, String group, UserToken token)
	{

		if(destFile.charAt(0) != '/')
		{
			destFile = "/" + destFile;
		}

		try
		{
			Envelope message = null, env = null;
			//Tell the server to return the member list
			message = new Envelope("UPLOADF");
			message.addObject(messageIndex);
			message.addObject(destFile);
			message.addObject(group);
			message.addObject(token); //Add requester's token
			message.addObject(getHMAC(message,false));
			output.writeObject(encryptCipher.doFinal(message.getBytes()));

			FileInputStream fis = new FileInputStream(sourceFile);

			env = Envelope.fromBytes(decryptCipher.doFinal((byte[]) input.readObject()));

			//If server indicates success, return the member list
			if(validateMessage(env) && env.getMessage().equals("READY"))
			{
				System.out.printf("Meta data upload successful\n");
			}
			else
			{
				System.out.printf("Upload failed: %s\n", env.getMessage());
				return false;
			}

			do
			{
				byte[] buf = new byte[4096];
				if(env.getMessage().compareTo("READY") != 0)
				{
					System.out.printf("Server error: %s\n", env.getMessage());
					return false;
				}
				message = new Envelope("CHUNK");
				message.addObject(messageIndex);
				int n = fis.read(buf); //can throw an IOException
				if(n > 0)
				{
					System.out.printf(".");
				}
				else if(n < 0)
				{
					System.out.println("Read error");
					return false;
				}

				message.addObject(buf);
				message.addObject(new Integer(n));
				message.addObject(getHMAC(message,false));
				output.writeObject(encryptCipher.doFinal(message.getBytes()));

				env = Envelope.fromBytes(decryptCipher.doFinal((byte[]) input.readObject()));


			} while(validateMessage(env) && fis.available() > 0);

			//If server indicates success, return the member list
			if(env.getMessage().compareTo("READY") == 0)
			{
				message = new Envelope("EOF");
				message.addObject(messageIndex);
				message.addObject(getHMAC(message,false));
				output.writeObject(encryptCipher.doFinal(message.getBytes()));

				env = Envelope.fromBytes(decryptCipher.doFinal((byte[]) input.readObject()));

				if(validateMessage(env) && env.getMessage().compareTo("OK") == 0)
				{
					System.out.printf("\nFile data upload successful\n");
				}
				else
				{
					System.out.printf("\nUpload failed: %s\n", env.getMessage());
					return false;
				}

			}
			else
			{
				System.out.printf("Upload failed: %s\n", env.getMessage());
				return false;
			}

		}
		catch(Exception e1)
		{
			System.err.println("Error: " + e1.getMessage());
			e1.printStackTrace(System.err);
			return false;
		}
		return true;
	}
}