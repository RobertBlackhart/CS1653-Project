/* Implements the GroupClient Interface */

import javax.crypto.Mac;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.List;

public class GroupClient extends Client implements GroupClientInterface
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

	public UserToken getToken(String username, String[] fileServerIPAndPort)
	{
		try
		{
			UserToken token = null;
			Envelope message = null, response = null;

			//Tell the server to return a token.
			message = new Envelope("GET");
			message.addObject(messageIndex);
			message.addObject(username); //Add user name string
			message.addObject(fileServerIPAndPort);
			message.addObject(getHMAC(message,false));
			output.writeObject(encryptCipher.doFinal(message.getBytes()));

			//Get the response from the server
			response = Envelope.fromBytes(decryptCipher.doFinal((byte[])input.readObject()));

			//Successful response
			if(validateMessage(response) && response.getMessage().equals("OK"))
			{
				//If there is a token in the Envelope, return it 
				if(response.getObjContents().get(1) instanceof UserToken)
					return (UserToken)response.getObjContents().get(1);
			}

			return null;
		}
		catch(Exception e)
		{
			e.printStackTrace();
			return null;
		}

	}

	public boolean createUser(String username, String weakSecret, UserToken token)
	{
		try
		{
			Envelope message = null, response = null;
			//Tell the server to create a user
			message = new Envelope("CUSER");
			message.addObject(messageIndex);
			message.addObject(username); //Add user name string
			message.addObject(weakSecret);
			message.addObject(token); //Add the requester's token
			message.addObject(getHMAC(message,false));
			output.writeObject(encryptCipher.doFinal(message.getBytes()));

			response = Envelope.fromBytes(decryptCipher.doFinal((byte[])input.readObject()));

			//If server indicates success, return true
			if(validateMessage(response) && response.getMessage().equals("OK"))
			{
				return true;
			}

			return false;
		}
		catch(Exception e)
		{
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
			return false;
		}
	}

	public boolean deleteUser(String username, UserToken token)
	{
		try
		{
			Envelope message = null, response = null;

			//Tell the server to delete a user
			message = new Envelope("DUSER");
			message.addObject(messageIndex);
			message.addObject(username); //Add user name
			message.addObject(token);  //Add requester's token
			message.addObject(getHMAC(message,false));
			output.writeObject(encryptCipher.doFinal(message.getBytes()));

			response = Envelope.fromBytes(decryptCipher.doFinal((byte[])input.readObject()));

			//If server indicates success, return true
			if(validateMessage(response) && response.getMessage().equals("OK"))
			{
				return true;
			}

			return false;
		}
		catch(Exception e)
		{
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
			return false;
		}
	}

	public boolean createGroup(String groupname, UserToken token)
	{
		try
		{
			Envelope message = null, response = null;
			//Tell the server to create a group
			message = new Envelope("CGROUP");
			message.addObject(messageIndex);
			message.addObject(groupname); //Add the group name string
			message.addObject(token); //Add the requester's token
			message.addObject(getHMAC(message,false));
			output.writeObject(encryptCipher.doFinal(message.getBytes()));

			response = Envelope.fromBytes(decryptCipher.doFinal((byte[])input.readObject()));

			//If server indicates success, return true
			if(validateMessage(response) && response.getMessage().equals("OK"))
			{
				return true;
			}

			return false;
		}
		catch(Exception e)
		{
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
			return false;
		}
	}

	public boolean deleteGroup(String groupname, UserToken token)
	{
		try
		{
			Envelope message = null, response = null;
			//Tell the server to delete a group
			message = new Envelope("DGROUP");
			message.addObject(messageIndex);
			message.addObject(groupname); //Add group name string
			message.addObject(token); //Add requester's token
			message.addObject(getHMAC(message,false));
			output.writeObject(encryptCipher.doFinal(message.getBytes()));

			response = Envelope.fromBytes(decryptCipher.doFinal((byte[])input.readObject()));

			//If server indicates success, return true
			if(validateMessage(response) && response.getMessage().equals("OK"))
			{
				return true;
			}

			return false;
		}
		catch(Exception e)
		{
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
			return false;
		}
	}

	@SuppressWarnings("unchecked")
	public List<String> listMembers(String group, UserToken token)
	{
		try
		{
			//Tell the server to return the member list
			Envelope message = new Envelope("LMEMBERS");
			message.addObject(messageIndex);
			message.addObject(group); //Add group name string
			message.addObject(token); //Add requester's token
			message.addObject(getHMAC(message,false));
			output.writeObject(encryptCipher.doFinal(message.getBytes()));

			Envelope response = Envelope.fromBytes(decryptCipher.doFinal((byte[])input.readObject()));

			//If server indicates success, return the member list
			if(validateMessage(response) && response.getMessage().equals("OK"))
			{
				return (List<String>) response.getObjContents().get(1);
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

	public boolean addUserToGroup(String username, String groupname, UserToken token)
	{
		try
		{
			Envelope message = null, response = null;
			//Tell the server to add a user to the group
			message = new Envelope("AUSERTOGROUP");
			message.addObject(messageIndex);
			message.addObject(username); //Add user name string
			message.addObject(groupname); //Add group name string
			message.addObject(token); //Add requester's token
			message.addObject(getHMAC(message,false));
			output.writeObject(encryptCipher.doFinal(message.getBytes()));

			response = Envelope.fromBytes(decryptCipher.doFinal((byte[])input.readObject()));

			//If server indicates success, return true
			if(validateMessage(response) && response.getMessage().equals("OK"))
			{
				return true;
			}

			return false;
		}
		catch(Exception e)
		{
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
			return false;
		}
	}

	public boolean deleteUserFromGroup(String username, String groupname, UserToken token)
	{
		try
		{
			Envelope message = null, response = null;
			//Tell the server to remove a user from the group
			message = new Envelope("RUSERFROMGROUP");
			message.addObject(messageIndex);
			message.addObject(username); //Add user name string
			message.addObject(groupname); //Add group name string
			message.addObject(token); //Add requester's token
			message.addObject(getHMAC(message,false));
			output.writeObject(encryptCipher.doFinal(message.getBytes()));

			response = Envelope.fromBytes(decryptCipher.doFinal((byte[])input.readObject()));

			//If server indicates success, return true
			if(validateMessage(response) && response.getMessage().equals("OK"))
			{
				return true;
			}

			return false;
		}
		catch(Exception e)
		{
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
			return false;
		}
	}
}