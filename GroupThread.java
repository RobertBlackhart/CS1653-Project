/* This thread does all the work. It communicates with the client through Envelopes.
 * 
 */

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.net.Socket;
import java.security.*;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;


public class GroupThread extends Thread
{
	private final Socket socket;
	private GroupServer my_gs;
	final byte[] ivBytes = new byte[]{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
	BigInteger messageIndex;

	public GroupThread(Socket _socket, GroupServer _gs)
	{
		socket = _socket;
		my_gs = _gs;
	}

	private byte[] getHMAC(Envelope envelope, boolean removeHMAC) throws NoSuchAlgorithmException, InvalidKeyException
	{
		//if last object in envelope is an hmac, remove it before computing
		if(removeHMAC)
			envelope.getObjContents().remove(envelope.getObjContents().size()-1);

		Mac mac = Mac.getInstance("HmacSHA1");
		mac.init(my_gs.signingKey);
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

	public void run()
	{
		boolean proceed = true;

		try
		{
			//Opens object streams and announces connection
			ObjectInputStream input = new ObjectInputStream(socket.getInputStream());
			ObjectOutputStream output = new ObjectOutputStream(socket.getOutputStream());
			String user = (String) input.readObject();

			//if the connection is from a file server, only give the public key
			if(user.equals("file_server"))
			{
				Envelope envelope = (Envelope)input.readObject();
				if(envelope != null && envelope.getMessage().equals("REQUESTPUBLICKEY"))
				{
					Envelope response = new Envelope("OK");
					response.addObject(my_gs.publicKey);
					output.writeObject(response);
				}
				socket.close();
				return;
			}

			System.out.println("*** New connection from " + user + socket.getInetAddress() + ":" + socket.getPort() + "***");

			String weakSecret = my_gs.userList.getUser(user).getWeakSecret();
			HashMap<String, SecretKey> secretKeys = DHKeyExchange.generateSecretKeyWithWeakSecret(user,weakSecret, input, output);
			if(secretKeys == null)
				throw new Exception("Unable to verify user");

			my_gs.encryptionKey = secretKeys.get("encryptionKey");
			my_gs.signingKey = secretKeys.get("signingKey");

			Cipher encryptCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
			Cipher decryptCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
			MessageDigest sha = MessageDigest.getInstance("SHA-1");
			byte[] key = sha.digest(my_gs.encryptionKey.getEncoded());
			key = Arrays.copyOf(key, 16); // use only first 128 bit

			SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");
			encryptCipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, new IvParameterSpec(ivBytes));
			decryptCipher.init(Cipher.DECRYPT_MODE, secretKeySpec, new IvParameterSpec(ivBytes));

			BigInteger C = new BigInteger(128,my_gs.random);
			BigInteger R = new BigInteger(decryptCipher.doFinal((byte[])input.readObject()));
			output.writeObject(encryptCipher.doFinal(R.add(C).toByteArray()));
			messageIndex = R.add(C);

			do
			{
				Envelope message = Envelope.fromBytes(decryptCipher.doFinal((byte[])input.readObject()));
				System.out.println("Request received: " + message.getMessage());
				Envelope response;

				if(!validateMessage(message))
				{
					response = new Envelope("FAIL-BADMESSAGE");
					response.addObject(messageIndex);
					response.addObject(getHMAC(response,false));
					output.writeObject(encryptCipher.doFinal(response.getBytes()));
					socket.close();
					return;
				}

				if(message.getMessage().equals("GET"))//Client wants a token
				{
					String username = (String) message.getObjContents().get(1); //Get the username
					String[] fileServerIPAndPort = (String[]) message.getObjContents().get(2);
					if(username == null || fileServerIPAndPort == null)
					{
						response = new Envelope("FAIL");
						response.addObject(messageIndex);
						response.addObject(null);
						response.addObject(getHMAC(response,false));
						output.writeObject(encryptCipher.doFinal(response.getBytes()));
					}
					else
					{
						UserToken yourToken = createToken(username,fileServerIPAndPort); //Create a token

						//Respond to the client. On error, the client will receive a null token
						response = new Envelope("OK");
						response.addObject(messageIndex);
						response.addObject(yourToken);
						response.addObject(getHMAC(response,false));
						output.writeObject(encryptCipher.doFinal(response.getBytes()));
					}
				}
				else if(message.getMessage().equals("CUSER")) //Client wants to create a user
				{
					if(message.getObjContents().size() < 3)
					{
						response = new Envelope("FAIL");
						response.addObject(messageIndex);
						response.addObject(getHMAC(response,false));
					}
					else
					{
						response = new Envelope("FAIL");
						response.addObject(messageIndex);
						response.addObject(getHMAC(response,false));

						if(message.getObjContents().get(1) != null)
						{
							if(message.getObjContents().get(2) != null)
							{
								String username = (String) message.getObjContents().get(1); //Extract the username
								weakSecret = (String) message.getObjContents().get(2);
								UserToken yourToken = (UserToken) message.getObjContents().get(3); //Extract the token

								if(validateToken(yourToken))
								{
									if(createUser(username, weakSecret, yourToken))
									{
										response = new Envelope("OK"); //Success
										response.addObject(messageIndex);
										response.addObject(getHMAC(response,false));
									}
								}
								else //if token fails validation check
								{
									response = new Envelope("FAIL-INVALIDTOKEN");
									response.addObject(messageIndex);
									response.addObject(getHMAC(response,false));
								}
							}
						}
					}

					output.writeObject(encryptCipher.doFinal(response.getBytes()));
				}
				else if(message.getMessage().equals("DUSER")) //Client wants to delete a user
				{
					if(message.getObjContents().size() < 3)
					{
						response = new Envelope("FAIL");
						response.addObject(messageIndex);
						response.addObject(getHMAC(response,false));
					}
					else
					{
						response = new Envelope("FAIL");
						response.addObject(messageIndex);
						response.addObject(getHMAC(response,false));

						if(message.getObjContents().get(1) != null)
						{
							if(message.getObjContents().get(2) != null)
							{
								String username = (String) message.getObjContents().get(1); //Extract the username
								UserToken yourToken = (UserToken) message.getObjContents().get(2); //Extract the token

								if(validateToken(yourToken))
								{
									if(deleteUser(username, yourToken))
									{
										response = new Envelope("OK"); //Success
										response.addObject(messageIndex);
										response.addObject(getHMAC(response,false));
									}
								}
								else //if token fails validation check
								{
									response = new Envelope("FAIL-INVALIDTOKEN");
									response.addObject(messageIndex);
									response.addObject(getHMAC(response,false));
								}
							}
						}
					}

					output.writeObject(encryptCipher.doFinal(response.getBytes()));
				}
				else if(message.getMessage().equals("CGROUP")) //Client wants to create a group
				{
					if(message.getObjContents().size() < 3)
					{
						response = new Envelope("FAIL");
						response.addObject(messageIndex);
						response.addObject(getHMAC(response,false));
					}
					else
					{
						//following procedure done in previous methods
						response = new Envelope("FAIL");
						response.addObject(messageIndex);
						response.addObject(getHMAC(response,false));

						if(message.getObjContents().get(1) != null)
						{
							if(message.getObjContents().get(2) != null)
							{
								//Extract the group name
								String groupname = (String) message.getObjContents().get(1);
								//Extract the token
								UserToken yourToken = (UserToken) message.getObjContents().get(2);

								if(validateToken(yourToken))
								{
									if(createGroup(groupname, yourToken))
									{
										response = new Envelope("OK"); //Success
										response.addObject(messageIndex);
										response.addObject(getHMAC(response,false));
									}
								}
								else //if token fails validation check
								{
									response = new Envelope("FAIL-INVALIDTOKEN");
									response.addObject(messageIndex);
									response.addObject(getHMAC(response,false));
								}
							}
						}
					}

					output.writeObject(encryptCipher.doFinal(response.getBytes()));
				}
				else if(message.getMessage().equals("DGROUP")) //Client wants to delete a group
				{
					/* TODO:  Write this handler */
					if(message.getObjContents().size() < 2)
					{
						response = new Envelope("FAIL");
						response.addObject(messageIndex);
						response.addObject(getHMAC(response,false));
					}
					else
					{
						response = new Envelope("FAIL");
						response.addObject(messageIndex);
						response.addObject(getHMAC(response,false));

						if(message.getObjContents().get(1) != null)
						{
							if(message.getObjContents().get(2) != null)
							{
								//grab the group name
								String groupname = (String) message.getObjContents().get(1);
								//grab token
								UserToken yourToken = (UserToken) message.getObjContents().get(2);

								if(validateToken(yourToken))
								{
									if(deleteGroup(groupname, yourToken))
									{
										response = new Envelope("OK"); //Success
										response.addObject(messageIndex);
										response.addObject(getHMAC(response,false));
									}
								}
								else //if token fails validation check
								{
									response = new Envelope("FAIL-INVALIDTOKEN");
									response.addObject(messageIndex);
									response.addObject(getHMAC(response,false));
								}
							}
						}
					}

					output.writeObject(encryptCipher.doFinal(response.getBytes()));
				}
				else if(message.getMessage().equals("LMEMBERS")) //Client wants a list of members in a group
				{
					//grab groupname
					String groupName = (String) message.getObjContents().get(1);
					//grab token
					UserToken yourToken = (UserToken) message.getObjContents().get(2);

					if(validateToken(yourToken))
					{
						if(groupName == null)
						{
							response = new Envelope("FAIL");
							response.addObject(messageIndex);
							response.addObject(null);
							response.addObject(getHMAC(response,false));
						}
						else
						{
							List<String> members = listMembers(groupName, yourToken);
							response = new Envelope("OK");
							response.addObject(messageIndex);
							response.addObject(members);
							response.addObject(getHMAC(response,false));
						}
					}
					else //if token fails validation check
					{
						System.out.println("fail");
						response = new Envelope("FAIL-INVALIDTOKEN");
						response.addObject(messageIndex);
						response.addObject(getHMAC(response,false));
					}

					output.writeObject(encryptCipher.doFinal(response.getBytes()));
				}
				else if(message.getMessage().equals("AUSERTOGROUP")) //Client wants to add user to a group
				{
					/* TODO:  Write this handler */
					//we need to check that this contains the groupname, username, and token
					if(message.getObjContents().size() < 4)
					{
						response = new Envelope("FAIL");
						response.addObject(messageIndex);
						response.addObject(getHMAC(response,false));
					}
					else
					{
						//this is the default
						response = new Envelope("FAIL");
						response.addObject(messageIndex);
						response.addObject(getHMAC(response,false));

						//check that all message fields are filled
						if(message.getObjContents().get(1) != null)
						{
							if(message.getObjContents().get(2) != null)
							{
								if(message.getObjContents().get(1) != null)
								{
									//grab username
									String username = (String) message.getObjContents().get(1);
									//grab groupname
									String groupname = (String) message.getObjContents().get(2);
									//grab token						
									UserToken yourToken = (UserToken) message.getObjContents().get(3);

									if(validateToken(yourToken))
									{
										if(addUserToGroup(username, groupname, yourToken))
										{
											response = new Envelope("OK");
											response.addObject(messageIndex);
											response.addObject(getHMAC(response,false));
										}
									}
									else //if token fails validation check
									{
										response = new Envelope("FAIL-INVALIDTOKEN");
										response.addObject(messageIndex);
										response.addObject(getHMAC(response,false));
									}
								}
							}
						}
					}

					output.writeObject(encryptCipher.doFinal(response.getBytes()));
				}
				else if(message.getMessage().equals("RUSERFROMGROUP")) //Client wants to remove user from a group
				{
					/* TODO:  Write this handler */
					//follow similiar logic to previous method
					if(message.getObjContents().size() < 4)
					{
						response = new Envelope("FAIL");
						response.addObject(messageIndex);
						response.addObject(getHMAC(response,false));
					}
					else
					{
						//this is the default
						response = new Envelope("FAIL");
						response.addObject(messageIndex);
						response.addObject(getHMAC(response,false));

						//check that all message fields are filled
						if(message.getObjContents().get(1) != null)
						{
							if(message.getObjContents().get(2) != null)
							{
								if(message.getObjContents().get(3) != null)
								{
									//grab username
									String username = (String) message.getObjContents().get(1);
									//grab groupname
									String groupname = (String) message.getObjContents().get(2);
									//grab token						
									UserToken yourToken = (UserToken) message.getObjContents().get(3);

									if(validateToken(yourToken))
									{
										if(deleteUserFromGroup(username, groupname, yourToken))
										{
											response = new Envelope("OK");
											response.addObject(messageIndex);
											response.addObject(getHMAC(response,false));
										}
									}
									else //if token fails validation check
									{
										response = new Envelope("FAIL-INVALIDTOKEN");
										response.addObject(messageIndex);
										response.addObject(getHMAC(response,false));
									}
								}
							}
						}
					}

					output.writeObject(encryptCipher.doFinal(response.getBytes()));
				}
				else if(message.getMessage().equals("DISCONNECT")) //Client wants to disconnect
				{
					socket.close(); //Close the socket
					proceed = false; //End this communication loop
				}
				else
				{
					response = new Envelope("FAIL"); //Server does not understand client request
					response.addObject(messageIndex);
					response.addObject(getHMAC(response,false));
					output.writeObject(encryptCipher.doFinal(response.getBytes()));
				}
			} while(proceed);
		}
		catch(Exception e)
		{
			e.printStackTrace();
			System.err.println("Error: " + e.getMessage());
		}
	}

	//Method to create tokens
	private UserToken createToken(String username, String[] fileServerIPAndPort)
	{
		//Check that user exists
		if(my_gs.userList.checkUser(username))
		{
			//Issue a new token with server's name, user's name, and user's groups
			UserToken yourToken = new Token(my_gs.name, username, my_gs.userList.getUserGroups(username),fileServerIPAndPort);
			//cryptographically sign token
			try
			{
				Signature signature = Signature.getInstance("SHA1withRSA");
				signature.initSign(GroupServer.privateKey);
				signature.update(yourToken.toByte());
				byte[] sig = signature.sign();
				yourToken.setSignature(sig);
				
				return yourToken;
			}
			catch(SignatureException SEx) 
			{
				System.out.println("Signature Failed: Signature Exception");
				SEx.printStackTrace();
				return null;
			}
			catch(NoSuchAlgorithmException NSAex)
			{
				System.out.println("Signature Failed: No Such Algorithm Exception");
				NSAex.printStackTrace();
				return null;
			}	
			catch(InvalidKeyException IKex)
			{
				System.out.println("Signature Failed: Invalid Key Exception Exception");
				IKex.printStackTrace();
				return null;
				
			}
		}
		else
		{
			return null;
		}
	}

	//Method to create a user
	private boolean createUser(String username, String weakSecret, UserToken yourToken)
	{
		String requester = yourToken.getSubject();

		//Check if requester exists
		if(my_gs.userList.checkUser(requester))
		{
			//Get the user's groups
			ArrayList<String> temp = my_gs.userList.getUserGroups(requester);
			//requester needs to be an administrator
			if(temp.contains("ADMIN"))
			{
				//Does user already exist?
				if(my_gs.userList.checkUser(username))
				{
					return false; //User already exists
				}
				else
				{
					my_gs.userList.addUser(username, weakSecret);
					return true;
				}
			}
			else
			{
				return false; //requester not an administrator
			}
		}
		else
		{
			return false; //requester does not exist
		}
	}

	//Method to delete a user
	private boolean deleteUser(String username, UserToken yourToken)
	{
		String requester = yourToken.getSubject();

		//Does requester exist?
		if(my_gs.userList.checkUser(requester))
		{
			ArrayList<String> temp = my_gs.userList.getUserGroups(requester);
			//requester needs to be an administer
			if(temp.contains("ADMIN"))
			{
				//Does user exist?
				if(my_gs.userList.checkUser(username))
				{
					//User needs deleted from the groups they belong
					ArrayList<String> deleteFromGroups = new ArrayList<String>();

					//This will produce a hard copy of the list of groups this user belongs
					for(int index = 0; index < my_gs.userList.getUserGroups(username).size(); index++)
					{
						deleteFromGroups.add(my_gs.userList.getUserGroups(username).get(index));
					}

					//Delete the user from the groups
					//If user is the owner, removeMember will automatically delete group!
					for(int index = 0; index < deleteFromGroups.size(); index++)
					{
						deleteUserFromGroup(username, deleteFromGroups.get(index), yourToken);
					}

					//If groups are owned, they must be deleted
					ArrayList<String> deleteOwnedGroup = new ArrayList<String>();

					//Make a hard copy of the user's ownership list
					for(int index = 0; index < my_gs.userList.getUserOwnership(username).size(); index++)
					{
						deleteOwnedGroup.add(my_gs.userList.getUserOwnership(username).get(index));
					}

					//Delete owned groups
					for(int index = 0; index < deleteOwnedGroup.size(); index++)
					{
						//Use the delete group method. Token must be created for this action
						deleteGroup(deleteOwnedGroup.get(index), yourToken);//new Token(my_gs.name, username, deleteOwnedGroup));
					}

					//Delete the user from the user list
					my_gs.userList.deleteUser(username);

					return true;
				}
				else
				{
					return false; //User does not exist

				}
			}
			else
			{
				return false; //requester is not an administer
			}
		}
		else
		{
			return false; //requester does not exist
		}
	}

	private boolean createGroup(String groupname, UserToken yourToken)
	{
		String requester = yourToken.getSubject();

		//verify token and requester. does this person exist
		if(my_gs.userList.checkUser(requester))
		{
			//check if the group name already exists
			//using Enumeration interface to more easily go through this loop
			//hasMoreElements is basically !empty
			for(String aUser : my_gs.userList.getUsernames())
			{
				if(my_gs.userList.getUserOwnership(aUser).contains(groupname))
				{
					return false;    //group name is therefore taken
				}
			}

			//add ownership
			my_gs.userList.addOwnership(requester, groupname);

			//add to groups
			my_gs.userList.addGroup(requester, groupname);

			return true;
		}
		else
		{
			//requester does not exist
			return false;
		}
	}

	private boolean deleteGroup(String groupname, UserToken yourToken)
	{
		String requester = yourToken.getSubject();

		//check if requester exists
		if(my_gs.userList.checkUser(requester))
		{
			/*  1)create a list
				2)go through usernameList and look for groups that match requesters ownership
				3)add these gorups to the list
				4) iterate through the smaller list and delete the specified group
			*/
			ArrayList<String> ownedGroups = new ArrayList<String>();
			for(int i = 0; i < my_gs.userList.getUserOwnership(requester).size(); i++)
			{
				ownedGroups.add(my_gs.userList.getUserOwnership(requester).get(i));
			}

			//check ownership, only the owner can delete the group
			if(ownedGroups.contains(groupname))
			{
				//not only do we have to remove this gorup, we have to remove it from
				//other users' list
				for(String aUser : my_gs.userList.getUsernames())
				{
					for(String ownedGroup : ownedGroups)
					{
						if(my_gs.userList.getUserGroups(aUser).contains(groupname))
						{
							my_gs.userList.removeGroup(aUser, groupname);
							my_gs.userList.removeOwnership(aUser,groupname);
						}
					}
				}

				//can't forget to remove it from the owner's list
				my_gs.userList.removeGroup(requester, groupname);

				return true;
			}
			else
			{
				//requester doesnt own the group, can't let him delete it
				return false;
			}
		}
		else
		{
			//requester doesn't exist
			return false;
		}
	}

	private List<String> listMembers(String group, UserToken yourToken)
	{
		String requester = yourToken.getSubject();
		List<String> aList = new ArrayList<String>();

		//check if requester exists
		if(my_gs.userList.checkUser(requester))
		{
			//only owners can list members
			ArrayList<String> ownedGroups = new ArrayList<String>();
			for(int i = 0; i < my_gs.userList.getUserOwnership(requester).size(); i++)
			{
				ownedGroups.add(my_gs.userList.getUserOwnership(requester).get(i));
			}

			//check ownership, only the owner can delete the group
			if(ownedGroups.contains(group))
			{
				// get a list of usernames, loop through each
				for(String aUser : my_gs.userList.getUsernames())
				{
					//if the user is in the group then add to aList
					if(my_gs.userList.getUserGroups(aUser).contains(group))
					{
						aList.add(aUser);
					}
				}

				//return list of members
				return aList;
			}
			//requester isn't in the group
			else
			{
				return null;
			}
		}
		else
		{
			return null;
		}
	}

	private boolean addUserToGroup(String username, String groupname, UserToken yourToken)
	{
		String requester = yourToken.getSubject();

		if(my_gs.userList.checkUser(requester) && my_gs.userList.checkUser(username))
		{
			//check if requester owns the group
			if(my_gs.userList.getUserOwnership(requester).contains(groupname))
			{
				//check if user is already part of group
				if(!my_gs.userList.getUserGroups(username).contains(groupname))
				{
					my_gs.userList.addGroup(username, groupname);
					//return confirmation of addition
					return true;
				}
				//user is already part of the group
				else
				{
					return false;
				}
			}
			//requester doesn't own group
			else
			{
				return false;
			}
		}
		else
		{
			return false;
		}
	}

	private boolean deleteUserFromGroup(String username, String groupname, UserToken yourToken)
	{
		String requester = yourToken.getSubject();

		if(my_gs.userList.checkUser(requester) && my_gs.userList.checkUser(username))
		{
			//check ownership
			if(my_gs.userList.getUserOwnership(requester).contains(groupname))
			{
				//can't delete someone who isnt part of the gorup
				if(my_gs.userList.getUserGroups(username).contains(groupname))
				{
					my_gs.userList.removeGroup(username, groupname);
					//confirmation of deletion
					return true;
				}
				//user isn't part of the group
				else
				{
					return false;
				}
			}
			else
			{
				return false;
			}
		}
		else
		{
			return false;
		}
	}

	//method to check if token is valid using group server's public key
	public boolean validateToken(UserToken usrToken)
	{
		try
		{
			Signature signature = Signature.getInstance("SHA1withRSA");
			signature.initVerify(my_gs.publicKey);
			signature.update(usrToken.toByte());
			if(signature.verify(usrToken.getSignature()))
			{
				return true;
			}
			else
			{
				return false;
			}
		}
		catch(GeneralSecurityException ex)
		{
			ex.printStackTrace();
		}
		return false;
	}
}
