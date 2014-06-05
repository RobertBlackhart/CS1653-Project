/* File worker thread handles the business of uploading, downloading, and removing files for clients with valid tokens */

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.math.BigInteger;
import java.net.Socket;
import java.security.*;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;


public class FileThread extends Thread
{
	private final Socket socket;
	private FileServer my_fs;
	final byte[] ivBytes = new byte[]{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
	BigInteger messageIndex;
	
	public FileThread(Socket _socket, FileServer fs)
	{
		socket = _socket;
		my_fs = fs;
	}

	private byte[] getHMAC(Envelope envelope, boolean removeHMAC) throws NoSuchAlgorithmException, InvalidKeyException
	{
		//if last object in envelope is an hmac, remove it before computing
		if(removeHMAC)
			envelope.getObjContents().remove(envelope.getObjContents().size()-1);

		Mac mac = Mac.getInstance("HmacSHA1");
		mac.init(my_fs.signingKey);
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
			final ObjectInputStream input = new ObjectInputStream(socket.getInputStream());
			final ObjectOutputStream output = new ObjectOutputStream(socket.getOutputStream());

			String username = (String) input.readObject();
			System.out.println("*** New connection from " + username + socket.getInetAddress() + ":" + socket.getPort() + "***");

			//send public key to user for inspection
			output.writeObject(my_fs.publicKey);

			//wait for acceptance
			String answer = (String) input.readObject();
			if(!answer.toLowerCase().equals("yes"))
			{
				return;
			}

			PublicKey usersPublic = (PublicKey) input.readObject();

			HashMap<String, SecretKey> secretKeys = DHKeyExchange.generateSecretKeySignedExchange(input, output, my_fs.privateKey, usersPublic);
			if(secretKeys == null)
			{
				throw new Exception("Unable to verify user");
			}
			my_fs.encryptionKey = secretKeys.get("encryptionKey");
			my_fs.signingKey = secretKeys.get("signingKey");

			Cipher encryptCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
			Cipher decryptCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
			MessageDigest sha = MessageDigest.getInstance("SHA-1");
			byte[] key = sha.digest(my_fs.encryptionKey.getEncoded());
			key = Arrays.copyOf(key, 16); // use only first 128 bit

			SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");
			encryptCipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, new IvParameterSpec(ivBytes));
			decryptCipher.init(Cipher.DECRYPT_MODE, secretKeySpec, new IvParameterSpec(ivBytes));

			BigInteger C = new BigInteger(128,my_fs.random);
			BigInteger R = new BigInteger(decryptCipher.doFinal((byte[])input.readObject()));
			output.writeObject(encryptCipher.doFinal(R.add(C).toByteArray()));
			messageIndex = R.add(C);

			Envelope response;

			do
			{
				Envelope e = Envelope.fromBytes(decryptCipher.doFinal((byte[]) input.readObject()));
				System.out.println("Request received: " + e.getMessage());

				if(!validateMessage(e))
				{
					response = new Envelope("FAIL-BADMESSAGE");
					response.addObject(messageIndex);
					response.addObject(getHMAC(response,false));
					output.writeObject(encryptCipher.doFinal(response.getBytes()));
					socket.close();
					return;
				}

				// Handler to list files that this user is allowed to see
				if(e.getMessage().equals("LFILES"))
				{
					if(e.getObjContents().size() < 1)
					{
						response = new Envelope("FAIL-BADCONTENTS");
						response.addObject(messageIndex);
						response.addObject(getHMAC(response,false));
					}
					else
					{
						try
						{
							UserToken token = (UserToken) e.getObjContents().get(1);
							
							/* 
								check if token is valid
							*/
							if(validateToken(token))
							{
								response = new Envelope("OK");
								response.addObject(messageIndex);
								ArrayList<String> returnList = new ArrayList<String>();

								for(ShareFile file : FileServer.fileList.getFiles())
								{
									if(token.getGroups().contains(file.getGroup()))
									{
										returnList.add(file.getPath());
									}
								}

								response.addObject(returnList);
								response.addObject(getHMAC(response,false));
							}
							else //if token fails validation check
							{
								response = new Envelope("FAIL-INVALIDTOKEN");
								response.addObject(messageIndex);
								response.addObject(getHMAC(response,false));
							}

						}
						catch(ClassCastException ex)
						{
							response = new Envelope("FAIL-BADTOKEN");
							response.addObject(messageIndex);
							response.addObject(getHMAC(response,false));
						}
					}

					output.writeObject(encryptCipher.doFinal(response.getBytes()));
				}
				else if(e.getMessage().equals("UPLOADF"))
				{
					if(e.getObjContents().size() < 4)
					{
						response = new Envelope("FAIL-BADCONTENTS");
						response.addObject(messageIndex);
						response.addObject(getHMAC(response,false));
					}
					else
					{
						if(e.getObjContents().get(1) == null)
						{
							response = new Envelope("FAIL-BADPATH");
							response.addObject(messageIndex);
							response.addObject(getHMAC(response,false));
						}
						if(e.getObjContents().get(2) == null)
						{
							response = new Envelope("FAIL-BADGROUP");
							response.addObject(messageIndex);
							response.addObject(getHMAC(response,false));
						}
						if(e.getObjContents().get(3) == null)
						{
							response = new Envelope("FAIL-BADTOKEN");
							response.addObject(messageIndex);
						}
						else
						{
							String remotePath = (String) e.getObjContents().get(1);
							String group = (String) e.getObjContents().get(2);
							UserToken yourToken = (UserToken) e.getObjContents().get(3); //Extract token
							if(validateToken(yourToken))
							{ //if token is valid, perform intended operation
								if(FileServer.fileList.checkFile(remotePath))
								{
									System.out.printf("Error: file already exists at %s\n", remotePath);
									response = new Envelope("FAIL-FILEEXISTS"); //Success
									response.addObject(messageIndex);
									response.addObject(getHMAC(response,false));
								}
								else if(!yourToken.getGroups().contains(group))
								{
									System.out.printf("Error: user missing valid token for group %s\n", group);
									response = new Envelope("FAIL-UNAUTHORIZED"); //Success
									response.addObject(messageIndex);
									response.addObject(getHMAC(response,false));
								}
								else
								{
									File file = new File("shared_files/" + remotePath.replace('/', '_'));
									file.createNewFile();
									FileOutputStream fos = new FileOutputStream(file);
									System.out.printf("Successfully created file %s\n", remotePath.replace('/', '_'));

									response = new Envelope("READY"); //Success
									response.addObject(messageIndex);
									response.addObject(getHMAC(response,false));
									output.writeObject(encryptCipher.doFinal(response.getBytes()));

									e = Envelope.fromBytes(decryptCipher.doFinal((byte[]) input.readObject()));

									while(validateMessage(e) && e.getMessage().compareTo("CHUNK") == 0)
									{
										fos.write((byte[]) e.getObjContents().get(1), 0, (Integer) e.getObjContents().get(2));
										response = new Envelope("READY"); //Success
										response.addObject(messageIndex);
										response.addObject(getHMAC(response,false));
										output.writeObject(encryptCipher.doFinal(response.getBytes()));
										e = Envelope.fromBytes(decryptCipher.doFinal((byte[]) input.readObject()));
									}

									if(e.getMessage().compareTo("EOF") == 0)
									{
										System.out.printf("Transfer successful file %s\n", remotePath);
										FileServer.fileList.addFile(yourToken.getSubject(), group, remotePath);
										response = new Envelope("OK"); //Success
										response.addObject(messageIndex);
										response.addObject(getHMAC(response,false));
									}
									else
									{
										System.out.printf("Error reading file %s from client\n", remotePath);
										response = new Envelope("ERROR-TRANSFER"); //Success
										response.addObject(messageIndex);
										response.addObject(getHMAC(response,false));
									}
									fos.close();
								}
							}
							else
							{ //if token is invalid, dont allow user to operate
								response = new Envelope("FAIL-INVALIDTOKEN");
								response.addObject(messageIndex);
								response.addObject(getHMAC(response,false));
							}
						}
					}

					output.writeObject(encryptCipher.doFinal(response.getBytes()));
				}
				else if(e.getMessage().compareTo("DOWNLOADF") == 0)
				{
					String remotePath = (String) e.getObjContents().get(1);
					Token t = (Token) e.getObjContents().get(2);
					
					/* 
						check if token is valid
					*/
					if(validateToken(t))
					{
						ShareFile sf = FileServer.fileList.getFile("/" + remotePath);
						if(sf == null)
						{
							System.out.printf("Error: File %s doesn't exist\n", remotePath);
							e = new Envelope("ERROR_FILEMISSING");
							e.addObject(messageIndex);
							e.addObject(getHMAC(e,false));
							output.writeObject(encryptCipher.doFinal(e.getBytes()));
						}
						else if(!t.getGroups().contains(sf.getGroup()))
						{
							System.out.printf("Error user %s doesn't have permission\n", t.getSubject());
							e = new Envelope("ERROR_PERMISSION");
							e.addObject(messageIndex);
							e.addObject(getHMAC(e,false));
							output.writeObject(encryptCipher.doFinal(e.getBytes()));
						}
						else
						{
							try
							{
								File f = new File("shared_files/_" + remotePath.replace('/', '_'));
								if(!f.exists())
								{
									System.out.printf("Error file %s missing from disk\n", "_" + remotePath.replace('/', '_'));
									e = new Envelope("ERROR_NOTONDISK");
									e.addObject(messageIndex);
									e.addObject(getHMAC(e,false));
									output.writeObject(encryptCipher.doFinal(e.getBytes()));
								}
								else
								{
									FileInputStream fis = new FileInputStream(f);

									do
									{
										byte[] buf = new byte[4096];
										if(e.getMessage().compareTo("DOWNLOADF") != 0)
										{
											System.out.printf("Server error: %s\n", e.getMessage());
											break;
										}
										e = new Envelope("CHUNK");
										e.addObject(messageIndex);
										int n = fis.read(buf); //can throw an IOException
										if(n > 0)
										{
											System.out.printf(".");
										}
										else if(n < 0)
										{
											System.out.println("Read error");

										}


										e.addObject(buf);
										e.addObject(new Integer(n));
										e.addObject(getHMAC(e,false));

										output.writeObject(encryptCipher.doFinal(e.getBytes()));

										e = Envelope.fromBytes(decryptCipher.doFinal((byte[]) input.readObject()));

									} while(validateMessage(e) && fis.available() > 0);

									//If server indicates success, return the member list
									if(e.getMessage().compareTo("DOWNLOADF") == 0)
									{
										e = new Envelope("EOF");
										e.addObject(messageIndex);
										e.addObject(getHMAC(e,false));
										output.writeObject(encryptCipher.doFinal(e.getBytes()));

										e = Envelope.fromBytes(decryptCipher.doFinal((byte[]) input.readObject()));

										if(validateMessage(e) && e.getMessage().compareTo("OK") == 0)
										{
											System.out.printf("File data upload successful\n");
										}
										else
										{
											System.out.printf("Upload failed: %s\n", e.getMessage());
										}
									}
									else
									{
										System.out.printf("Upload failed: %s\n", e.getMessage());
									}
								}
							}
							catch(Exception e1)
							{
								System.err.println("Error: " + e.getMessage());
								e1.printStackTrace(System.err);
							}
						}
					}
					else
					{
						System.out.println("token is invalid");
						e = new Envelope("FAIL-INVALIDTOKEN");
						e.addObject(messageIndex);
						e.addObject(getHMAC(e,false));
						output.writeObject(encryptCipher.doFinal(e.getBytes()));
					}
				}
				else if(e.getMessage().compareTo("DELETEF") == 0)
				{
					String remotePath = (String) e.getObjContents().get(1);
					Token t = (Token) e.getObjContents().get(2);
					if(validateToken(t))
					{
						ShareFile sf = FileServer.fileList.getFile("/" + remotePath);
						if(sf == null)
						{
							System.out.printf("Error: File %s doesn't exist\n", remotePath);
							e = new Envelope("ERROR_DOESNTEXIST");
							e.addObject(messageIndex);
							e.addObject(getHMAC(e,false));
						}
						else if(!t.getGroups().contains(sf.getGroup()))
						{
							System.out.printf("Error user %s doesn't have permission\n", t.getSubject());
							e = new Envelope("ERROR_PERMISSION");
							e.addObject(messageIndex);
							e.addObject(getHMAC(e,false));
						}
						else
						{
							try
							{
								File f = new File("shared_files/" + "_" + remotePath.replace('/', '_'));

								if(!f.exists())
								{
									System.out.printf("Error file %s missing from disk\n", "_" + remotePath.replace('/', '_'));
									e = new Envelope("ERROR_FILEMISSING");
									e.addObject(messageIndex);
									e.addObject(getHMAC(e,false));
								}
								else if(f.delete())
								{
									System.out.printf("File %s deleted from disk\n", "_" + remotePath.replace('/', '_'));
									FileServer.fileList.removeFile("/" + remotePath);
									e = new Envelope("OK");
									e.addObject(messageIndex);
									e.addObject(getHMAC(e,false));
								}
								else
								{
									System.out.printf("Error deleting file %s from disk\n", "_" + remotePath.replace('/', '_'));
									e = new Envelope("ERROR_DELETE");
									e.addObject(messageIndex);
									e.addObject(getHMAC(e,false));
								}
							}
							catch(Exception e1)
							{
								System.err.println("Error: " + e1.getMessage());
								e1.printStackTrace(System.err);
								e = new Envelope(e1.getMessage());
								e.addObject(messageIndex);
								e.addObject(getHMAC(e,false));
							}
						}
					}
					else
					{    //token failed the validate method
						e = new Envelope("FAIL-INVALIDTOKEN");
						e.addObject(messageIndex);
						e.addObject(getHMAC(e,false));
					}
					output.writeObject(encryptCipher.doFinal(e.getBytes()));
				}
				else if(e.getMessage().equals("DISCONNECT"))
				{
					socket.close();
					proceed = false;
				}
			} while(proceed);
		}
		catch(Exception e)
		{
			System.err.println("Error: " + e.getMessage());
		}
	}

	//method to check if token is valid using group server's public key
	public boolean validateToken(UserToken usrToken)
	{
		try
		{
			boolean ipEqual = socket.getInetAddress().toString().equals(usrToken.getFileServerIPAndPort()[0]);
			boolean portEqual = String.valueOf(socket.getLocalPort()).equals(usrToken.getFileServerIPAndPort()[1]);
			Signature signature = Signature.getInstance("SHA1withRSA");
			signature.initVerify(my_fs.groupPublicKey);
			signature.update(usrToken.toByte());
			if(signature.verify(usrToken.getSignature()) && ipEqual && portEqual)
			{
				return true;
			}
			else
			{
				System.out.println("could not validate token");
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