import org.apache.commons.lang3.SerializationUtils;

import java.util.ArrayList;


public class Envelope implements java.io.Serializable
{

	/**
	 *
	 */
	private static final long serialVersionUID = -7726335089122193103L;
	private String msg;
	private ArrayList<Object> objContents = new ArrayList<Object>();

	public Envelope(String text)
	{
		msg = text;
	}

	public String getMessage()
	{
		return msg;
	}

	public ArrayList<Object> getObjContents()
	{
		return objContents;
	}

	public void addObject(Object object)
	{
		objContents.add(object);
	}

	public byte[] getBytes()
	{
		return SerializationUtils.serialize(this);
	}

	public static Envelope fromBytes(byte[] bytes)
	{
		return SerializationUtils.deserialize(bytes);
	}
}
