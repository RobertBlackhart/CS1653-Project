import java.util.List;
import java.util.Scanner;

/**
 * Name:  Robert McDermot
 * Email: rom66@pitt.edu
 * ID #:  ***2800
 * Date:  2/5/14
 */
public class ClientApp
{
	public static void main(String[]args)
	{
		Scanner scanner = new Scanner(System.in);
		System.out.print("Login as: ");
		String username = scanner.nextLine();
		System.out.print("password: " );
		String weakSecret = scanner.nextLine();

		System.out.print("IP address of group server: ");
		String[] groupIP = scanner.nextLine().split(" ");
		int groupPort = 8765;
		try
		{
			if(groupIP.length > 1)
				groupPort = Integer.parseInt(groupIP[1]);
		}
		catch(NumberFormatException ex)
		{
			System.out.println("Could not parse " + groupIP[1] + " into a number. Exiting.");
			System.exit(-1);
		}

		System.out.print("IP address of file server: ");
		String[] fileIP = scanner.nextLine().split(" ");
		int filePort = 4321;
		try
		{
			if(fileIP.length > 1)
				filePort = Integer.parseInt(fileIP[1]);
		}
		catch(NumberFormatException ex)
		{
			System.out.println("Could not parse " + fileIP[1] + " into a number. Exiting.");
			System.exit(-1);
		}

		FileClient fileClient = new FileClient();
		fileClient.connect(username,null,fileIP[0], filePort);
		String[] inetAddress = {fileClient.sock.getLocalAddress().toString(),String.valueOf(filePort)};

		if(!fileClient.isConnected())
		{
			System.out.println("Could not connect to the file server at " + fileIP[0] + ":" + filePort + ". Exiting");
			System.exit(-1);
		}

		GroupClient groupClient = new GroupClient();
		groupClient.connect(username,weakSecret,groupIP[0], groupPort);
		Token token = (Token) groupClient.getToken(username,inetAddress);

		if(!groupClient.isConnected() || token == null)
		{
			System.out.println("Could not connect to the group server at " + groupIP[0] + ":" + groupPort + " with username " + username + " and password " + weakSecret + ". Exiting.");
			System.exit(-1);
		}

		while(true)
		{
			System.out.print(username+"@"+groupIP[0]+">");
			String line = scanner.nextLine();
			while(line.trim().length() == 0)
				line = scanner.nextLine();

			if(line.startsWith("help"))
			{
				System.out.println("List of available commands:\nGroup Commands\n" +
															  "--------------" +
															  "\nconnectGroupServer\t\t<group_server_ip> <port>" +
															  "\ndisconnectGroupServer" +
															  "\ngetToken\t\t\t\t<username>" +
															  "\ncreateUser\t\t\t\t<username> <weaksecret>" +
															  "\ndeleteUser\t\t\t\t<username>" +
															  "\ncreateGroup\t\t\t\t<groupname>" +
															  "\ndeleteGroup\t\t\t\t<groupname>" +
															  "\naddUserToGroup\t\t\t<username> <groupname>" +
															  "\ndeleteUserFromGroup\t\t<username> <groupname>" +
															  "\nlistMembers\t\t\t\t<groupname>" +
															  "\n\nFileCommands\n" +
															  "--------------" +
															  "\nconnectFileServer		<file_server_ip> <port>" +
															  "\ndisconnectFileServer" +
															  "\nlistFiles" +
															  "\nupload\t\t\t\t\t<source_file_path> <dest_file_name> <group>" +
															  "\ndownload\t\t\t\t<remote_file_name> <local_file_path>" +
															  "\ndelete\t\t\t\t\t<remote_file_name>" +
															  "\n\nexit\n");
			}
			else if(line.startsWith("connectGroupServer"))
			{
				String[] command = line.split(" ");
				if(command.length != 3)
				{
					System.out.println("Usage: connect <group_server_ip> <port>");
					continue;
				}
				else
				{
					groupClient.disconnect();
					try
					{
						boolean success = groupClient.connect(username,weakSecret,command[1],Integer.parseInt(command[2]));
						if(!success)
							System.out.println("Unable to connect to " + command[1] + " on port " + command[2]);
						else
							System.out.println("Connected to " + command[1] + " on port " + command[2]);
					}
					catch(NumberFormatException ex)
					{
						System.err.println("<port> must be an integer");
					}
				}
			}
			else if(line.startsWith("disconnectGroupServer"))
			{
				if(!groupClient.isConnected())
				{
					System.out.println("Not currently connected");
					continue;
				}

				groupClient.disconnect();
			}
			else if(line.startsWith("getToken"))
			{
				if(!groupClient.isConnected())
				{
					System.out.println("Not currently connected");
					continue;
				}

				String[] command = line.split(" ");
				if(command.length != 4)
				{
					System.out.println("Usage: <username> <fileServerIP> <fileServerPort>");
					continue;
				}

				String[] fileServerIPAndPort = {command[2],command[3]};

				Token temp = (Token) groupClient.getToken(command[1],fileServerIPAndPort);
				if(temp != null)
				{
					token = temp;
					System.out.println("Successfully got token for " + command[1]);
				}
				else
					System.out.println("Error getting token for " + command[1]);
			}
			//these pair of methods are above addUser and deleteUser because of the use of line.startsWith
			else if(line.startsWith("addUserToGroup"))
			{
				if(!groupClient.isConnected())
				{
					System.out.println("Not currently connected");
					continue;
				}

				String[] command = line.split(" ");
				if(command.length != 3)
				{
					System.out.println("Usage: <username> <groupname>");
					continue;
				}

				if(groupClient.addUserToGroup(command[1], command[2], token))
					System.out.println("Successfully added " + command[1] + " to " + command[2]);
				else
					System.out.println("Error adding " + command[1] + " to " + command[2]);
			}
			else if(line.startsWith("deleteUserFromGroup"))
			{
				if(!groupClient.isConnected())
				{
					System.out.println("Not currently connected");
					continue;
				}

				String[] command = line.split(" ");
				if(command.length != 3)
				{
					System.out.println("Usage: <username> <groupname>");
					continue;
				}

				if(groupClient.deleteUserFromGroup(command[1], command[2], token))
					System.out.println("Successfully deleted " + command[1] + " from " + command[2]);
				else
					System.out.println("Error deleting " + command[1] + " from " + command[2]);
			}
			else if(line.startsWith("createUser"))
			{
				if(!groupClient.isConnected())
				{
					System.out.println("Not currently connected");
					continue;
				}

				String[] command = line.split(" ");
				if(command.length != 3)
				{
					System.out.println("Usage: <username> <weaksecret>");
					continue;
				}

				if(groupClient.createUser(command[1],command[2],token))
					System.out.println("Successfully created user: " + command[1]);
				else
					System.out.println("Error creating user: " + command[1]);
			}
			else if(line.startsWith("deleteUser"))
			{
				if(!groupClient.isConnected())
				{
					System.out.println("Not currently connected");
					continue;
				}

				String[] command = line.split(" ");
				if(command.length != 2)
				{
					System.out.println("Usage: <username>");
					continue;
				}

				if(groupClient.deleteUser(command[1], token))
					System.out.println("Successfully deleted user: " + command[1]);
				else
					System.out.println("Error deleting user: " + command[1]);
			}
			else if(line.startsWith("createGroup"))
			{
				if(!groupClient.isConnected())
				{
					System.out.println("Not currently connected");
					continue;
				}

				String[] command = line.split(" ");
				if(command.length != 2)
				{
					System.out.println("Usage: <groupname>");
					continue;
				}

				if(groupClient.createGroup(command[1], token))
					System.out.println("Successfully created group: " + command[1]);
				else
					System.out.println("Error creating group: " + command[1]);
			}
			else if(line.startsWith("deleteGroup"))
			{
				if(!groupClient.isConnected())
				{
					System.out.println("Not currently connected");
					continue;
				}

				String[] command = line.split(" ");
				if(command.length != 2)
				{
					System.out.println("Usage: <groupname>");
					continue;
				}

				if(groupClient.deleteGroup(command[1], token))
					System.out.println("Successfully deleted group: " + command[1]);
				else
					System.out.println("Error deleting group: " + command[1]);
			}
			else if(line.startsWith("listMembers"))
			{
				if(!groupClient.isConnected())
				{
					System.out.println("Not currently connected");
					continue;
				}

				String[] command = line.split(" ");
				if(command.length != 2)
				{
					System.out.println("Usage: <groupname>");
					continue;
				}

				System.out.println("List of members in group " + command[1] + ":\n");
				List<String> memberList = groupClient.listMembers(command[1],token);
				if(memberList == null)
					System.out.println("No members to display");
				else
				{
					for(String member : memberList)
						System.out.println(member);
				}
			}
			else if(line.startsWith("connectFileServer"))
			{
				String[] command = line.split(" ");
				if(command.length != 3)
				{
					System.out.println("Usage: connect <file_server_ip> <port>");
					continue;
				}
				else
				{
					fileClient.disconnect();
					try
					{
						boolean success = fileClient.connect(username,null,command[1],Integer.parseInt(command[2]));
						if(!success)
							System.out.println("Unable to connect to " + command[1] + " on port " + command[2]);
						else
							System.out.println("Connected to " + command[1] + " on port " + command[2]);
					}
					catch(NumberFormatException ex)
					{
						System.err.println("<port> must be an integer");
					}
				}
			}
			else if(line.startsWith("disconnectFileServer"))
			{
				if(!fileClient.isConnected())
				{
					System.out.println("Not currently connected");
					continue;
				}

				fileClient.disconnect();
			}
			else if(line.startsWith("listFiles"))
			{
				if(!fileClient.isConnected())
				{
					System.out.println("Not currently connected");
					continue;
				}

				System.out.println("List of files on the server:\n");
				List<String> files = fileClient.listFiles(token);
				if(files == null)
					System.out.println("Cannot list files");
				else
				{
					for(String file : files)
						System.out.println(file);
				}
			}
			else if(line.startsWith("upload"))
			{
				if(!fileClient.isConnected())
				{
					System.out.println("Not currently connected");
					continue;
				}

				String[] command = line.split(" ");
				if(command.length != 4)
				{
					System.out.println("Usage: <source_file_path> <dest_file_name> <group>");
					continue;
				}

				fileClient.upload(command[1],command[2],command[3],token);
			}
			else if(line.startsWith("download"))
			{
				if(!fileClient.isConnected())
				{
					System.out.println("Not currently connected");
					continue;
				}

				String[] command = line.split(" ");
				if(command.length != 3)
				{
					System.out.println("Usage: <remote_file_name> <local_file_path>");
					continue;
				}

				fileClient.download(command[1],command[2],token);
			}
			else if(line.startsWith("delete"))
			{
				if(!fileClient.isConnected())
				{
					System.out.println("Not currently connected");
					continue;
				}

				String[] command = line.split(" ");
				if(command.length != 2)
				{
					System.out.println("Usage: <remote_file_name>");
					continue;
				}

				fileClient.delete(command[1],token);
			}
			else if(line.startsWith("exit"))
			{
				System.exit(0);
			}
			else
			{
				System.out.println("Command not recognized.  Type 'help' to get a list of available commands");
			}
		}
	}
}
