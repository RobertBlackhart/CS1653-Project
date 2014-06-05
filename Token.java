import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

public class Token implements UserToken, Serializable
{
	public String issuer;
	public String subject;
	public String[] fileServerIPAndPort;
	public List<String> groups;
	private byte[] signature;

	public Token(String gsName, String username, ArrayList<String> userList, String[] fileServerIPAndPort)
	{
		this.issuer = gsName;
		this.subject = username;
		this.groups = userList;
		this.fileServerIPAndPort = fileServerIPAndPort;
	}

	//essentially gives the name of the group server
	public String getIssuer()
	{
		return issuer;
	}

	//returns the name with whom the token is associated with
	public String getSubject()
	{
		return subject;
	}

	//list the groups that the subject (see above) is associated with
	public List<String> getGroups()
	{
		return groups;
	}

	@Override
	public String[] getFileServerIPAndPort()
	{
		return fileServerIPAndPort;
	}

	//return a byte array of concatonated string fields to be signed by Group Thread
	public byte[] toByte()
	{
		try
		{
			ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

			//write issuer
			outputStream.write(issuer.getBytes());

			//write subject
			outputStream.write(subject.getBytes());

			//write groups
			for(String s : this.groups)
				outputStream.write(s.getBytes());

			//write the fileServerIP
			for(String s : fileServerIPAndPort)
				outputStream.write(s.getBytes());

			return outputStream.toByteArray();
		}
		catch(IOException e)
		{
			System.out.println("IOEXCEPTION in Token.java.  Failed to write to bytestream");
		}

		return null;
	}

	//set the tokens signature
	public void setSignature(byte[] sig)
	{
		this.signature = sig;
	}

	//return the signature
	public byte[] getSignature()
	{
		return this.signature;
	}
}
