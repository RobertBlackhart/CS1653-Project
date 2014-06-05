/* This list represents the users on the server */

import java.util.*;


public class UserList implements java.io.Serializable
{

	/**
	 *
	 */
	private static final long serialVersionUID = 7600343803563417992L;
	private Hashtable<String, User> list = new Hashtable<String, User>();

	public synchronized void addUser(String username, String weakSecret)
	{
		User newUser = new User(weakSecret);
		list.put(username, newUser);
	}

	public synchronized void deleteUser(String username)
	{
		list.remove(username);
	}

	public synchronized boolean checkUser(String username)
	{
		if(list.containsKey(username))
		{
			return true;
		}
		else
		{
			return false;
		}
	}

	public synchronized User getUser(String username)
	{
		return list.get(username);
	}

	public synchronized ArrayList<String> getUserGroups(String username)
	{
		return list.get(username).getGroups();
	}

	public synchronized ArrayList<String> getUserOwnership(String username)
	{
		return list.get(username).getOwnership();
	}

	public synchronized void addGroup(String user, String groupname)
	{
		list.get(user).addGroup(groupname);
	}

	public synchronized void removeGroup(String user, String groupname)
	{
		list.get(user).removeGroup(groupname);
	}

	public synchronized void addOwnership(String user, String groupname)
	{
		list.get(user).addOwnership(groupname);
	}

	public synchronized void removeOwnership(String user, String groupname)
	{
		list.get(user).removeOwnership(groupname);
	}

	//add this for GroupThread. returns usernames
	public synchronized ArrayList<String> getUsernames()
	{
		return new ArrayList<String>(list.keySet());
	}

	class User implements java.io.Serializable
	{

		/**
		 *
		 */
		private static final long serialVersionUID = -6699986336399821598L;
		private ArrayList<String> groups;
		private ArrayList<String> ownership;
		private String weakSecret;

		public User(String secret)
		{
			weakSecret = secret;
			groups = new ArrayList<String>();
			ownership = new ArrayList<String>();
		}

		public ArrayList<String> getGroups()
		{
			return groups;
		}

		public ArrayList<String> getOwnership()
		{
			return ownership;
		}

		public void addGroup(String group)
		{
			groups.add(group);
		}

		public void removeGroup(String group)
		{
			if(!groups.isEmpty())
			{
				if(groups.contains(group))
				{
					groups.remove(groups.indexOf(group));
				}
			}
		}

		public void addOwnership(String group)
		{
			ownership.add(group);
		}

		public void removeOwnership(String group)
		{
			if(!ownership.isEmpty())
			{
				if(ownership.contains(group))
				{
					ownership.remove(ownership.indexOf(group));
				}
			}
		}

		public String getWeakSecret()
		{
			return weakSecret;
		}

		public void setWeakSecret(String weakSecret)
		{
			this.weakSecret = weakSecret;
		}
	}

}	