
import java.util.List;

/**
 * A simple interface to the token data structure that will be
 * returned by a group server.  
 *
 * You will need to develop a class that implements this interface so
 * that your code can interface with the tokens created by your group
 * server.
 *
 */
public interface UserToken
{
    /**
     * This method should return a string describing the issuer of
     * this token.  This string identifies the group server that
     * created this token.  For instance, if "Alice" requests a token
     * from the group server "Server1", this method will return the
     * string "Server1".
     *
     * @return The issuer of this token
     *
     */
    public String getIssuer();


    /**
     * This method should return a string indicating the name of the
     * subject of the token.  For instance, if "Alice" requests a
     * token from the group server "Server1", this method will return
     * the string "Alice".
     *
     * @return The subject of this token
     *
     */
    public String getSubject();


    /**
     * This method extracts the list of groups that the owner of this
     * token has access to.  If "Alice" is a member of the groups "G1"
     * and "G2" defined at the group server "Server1", this method
     * will return ["G1", "G2"].
     *
     * @return The list of group memberships encoded in this token
     *
     */
    public List<String> getGroups();
	
	
	
	/**
	 *This method will return a string of concatenated token contents
	 *to be passed from Group Server to User. Group Membership will always be 
	 *in a fixed order because they are stored in an Array List
	 *Fields in byte array are seperated by semicolons
	 *
	 *@return A byte array consisting of all token data members in
	 */
	 public byte[] toByte();
	 
	 
	 /**
	 *This method will set the signature variable of the token
	 *
	 *
	 *@return nothing
	 */
	 public void setSignature(byte[] sig);
	 
	 /**
	 *This method will return the signature contained in the user token
	 *Used for the purpose of veryfying the signature
	 *
	 *@return byte array containing the signature supplied by the group server
	 */
	 public byte[] getSignature();

	 /**
	 *This method will return the file server IP to prevent token theft
	 *by the file server
	 *
	 *@return fileServerIP
	 */
	 public String[] getFileServerIPAndPort();
	 

}   //-- end interface UserToken
