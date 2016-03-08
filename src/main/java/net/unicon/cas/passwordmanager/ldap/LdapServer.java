package net.unicon.cas.passwordmanager.ldap;

import net.unicon.cas.passwordmanager.UserNotFoundException;
import net.unicon.cas.passwordmanager.flow.SecurityChallenge;

import org.ldaptive.AttributeModification;
import org.ldaptive.LdapException;

public interface LdapServer {
	
	public void ldapModify(String username, AttributeModification... modifications)
			throws LdapException, UserNotFoundException;
	
	public void setPassword(String username, String password) throws LdapException, UserNotFoundException;
	
//	public boolean verifyPassword(String username, String password);
	
	public SecurityChallenge getUserSecurityChallenge(String username) throws LdapException, UserNotFoundException;
	
	public void setUserSecurityChallenge(String username, SecurityChallenge securityChallenge) throws LdapException, UserNotFoundException;
	
//	public SecurityChallenge getDefaultSecurityChallenge(String username);
	
	/**
	 * <p>Gets a user-specified description for logging purposes</p>
	 * @return server description
	 */
	public String getDescription();

	public void changePassword(String username, String oldPassword,
			String newPassword) throws LdapException, UserNotFoundException;
    
    public boolean verifyAttribute(String username, String name, String value) throws LdapException, UserNotFoundException;
}
