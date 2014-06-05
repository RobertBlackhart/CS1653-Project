/* FileServer loads files from FileList.bin.  Stores files in shared_files directory. */

import javax.crypto.SecretKey;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Scanner;

public class FileServer extends Server
{
	public static final int SERVER_PORT = 4321;
	public static FileList fileList;
	protected SecretKey encryptionKey, signingKey;
	public PublicKey publicKey, groupPublicKey;
	public PrivateKey privateKey;

	public FileServer()
	{
		super(SERVER_PORT, "FilePile");
	}

	public FileServer(int _port)
	{
		super(_port, "FilePile");
	}

	public void start()
	{
		String fileFile = "FileList.bin";
		String keyFilePath = "KeyFile.bin";
		ObjectInputStream fileStream;

		try
		{
			Scanner scanner = new Scanner(System.in);
			//request public key from group server
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
			Socket socket = new Socket(groupIP[0], groupPort);
			ObjectOutputStream output = new ObjectOutputStream(socket.getOutputStream());
			ObjectInputStream input = new ObjectInputStream(socket.getInputStream());

			//send username as "file_server" so the group server knows we aren't a normal user
			output.writeObject("file_server");

			Envelope send = new Envelope("REQUESTPUBLICKEY");
			output.writeObject(send);

			Envelope response = (Envelope) input.readObject();
			if(response != null && response.getMessage().equals("OK"))
				groupPublicKey = (PublicKey) response.getObjContents().get(0);
			else
			{
				System.out.println("Could not obtain public key from group server. Exiting.");
				System.exit(-1);
			}

			File keyFile = new File(keyFilePath);
			if(keyFile.exists())
			{
				FileInputStream fis = new FileInputStream(keyFilePath);
				fileStream = new ObjectInputStream(fis);
				publicKey = (PublicKey) fileStream.readObject();
				privateKey = (PrivateKey) fileStream.readObject();
				if(publicKey == null || privateKey == null)
					throw new Exception("Could not read public/private keys from file");
			}
			else
			{
				System.out.println("Creating new Keypair");
				keyFile.createNewFile();
				KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
				keyGen.initialize(1024);
				KeyPair keys = keyGen.generateKeyPair();
				publicKey = keys.getPublic();
				privateKey = keys.getPrivate();
				ObjectOutputStream outputStream = new ObjectOutputStream(new FileOutputStream(keyFile));
				outputStream.writeObject(publicKey);
				outputStream.writeObject(privateKey);
				outputStream.flush();
				outputStream.close();
			}
		}
		catch(Exception ex)
		{
			System.out.println("Could not generate or access RSA keypair");
			System.exit(-1);
		}

		//This runs a thread that saves the lists on program exit
		Runtime runtime = Runtime.getRuntime();
		Thread catchExit = new Thread(new ShutDownListenerFS());
		runtime.addShutdownHook(catchExit);

		//Open user file to get user list
		try
		{
			FileInputStream fis = new FileInputStream(fileFile);
			fileStream = new ObjectInputStream(fis);
			fileList = (FileList) fileStream.readObject();
		}
		catch(FileNotFoundException e)
		{
			System.out.println("FileList Does Not Exist. Creating FileList...");

			fileList = new FileList();

		}
		catch(IOException e)
		{
			System.out.println("Error reading from FileList file");
			System.exit(-1);
		}
		catch(ClassNotFoundException e)
		{
			System.out.println("Error reading from FileList file");
			System.exit(-1);
		}

		File file = new File("shared_files");
		if(file.mkdir())
		{
			System.out.println("Created new shared_files directory");
		}
		else if(file.exists())
		{
			System.out.println("Found shared_files directory");
		}
		else
		{
			System.out.println("Error creating shared_files directory");
		}

		//Autosave Daemon. Saves lists every 5 minutes
		AutoSaveFS aSave = new AutoSaveFS();
		aSave.setDaemon(true);
		aSave.start();


		boolean running = true;

		try
		{
			final ServerSocket serverSock = new ServerSocket(port);
			System.out.printf("%s up and running\n", this.getClass().getName());

			Socket sock = null;
			Thread thread = null;

			while(running)
			{
				sock = serverSock.accept();
				thread = new FileThread(sock,this);
				thread.start();
			}

			System.out.printf("%s shut down\n", this.getClass().getName());
		}
		catch(Exception e)
		{
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
		}
	}
}

//This thread saves user and group lists
class ShutDownListenerFS implements Runnable
{
	public void run()
	{
		System.out.println("Shutting down server");
		ObjectOutputStream outStream;

		try
		{
			outStream = new ObjectOutputStream(new FileOutputStream("FileList.bin"));
			outStream.writeObject(FileServer.fileList);
		}
		catch(Exception e)
		{
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
		}
	}
}

class AutoSaveFS extends Thread
{
	public void run()
	{
		do
		{
			try
			{
				Thread.sleep(300000); //Save group and user lists every 5 minutes
				System.out.println("Autosave file list...");
				ObjectOutputStream outStream;
				try
				{
					outStream = new ObjectOutputStream(new FileOutputStream("FileList.bin"));
					outStream.writeObject(FileServer.fileList);
				}
				catch(Exception e)
				{
					System.err.println("Error: " + e.getMessage());
					e.printStackTrace(System.err);
				}

			}
			catch(Exception e)
			{
				System.out.println("Autosave Interrupted");
			}
		} while(true);
	}
}
