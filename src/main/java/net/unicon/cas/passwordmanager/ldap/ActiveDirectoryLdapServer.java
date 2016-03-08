package net.unicon.cas.passwordmanager.ldap;

import java.io.UnsupportedEncodingException;
import javax.validation.constraints.NotNull;

import net.unicon.cas.passwordmanager.PasswordManagerException;
import net.unicon.cas.passwordmanager.UserNotFoundException;

import org.ldaptive.*;
import org.ldaptive.auth.AuthenticationRequest;
import org.ldaptive.auth.AuthenticationResponse;
import org.ldaptive.auth.Authenticator;
import org.ldaptive.handler.HandlerResult;
import org.ldaptive.handler.OperationExceptionHandler;
import org.ldaptive.handler.OperationResponseHandler;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static org.ldaptive.AttributeModificationType.*;

/**
 * 
 * @author Harvey McQueen <hmcqueen at gmail.com>
 */
public class ActiveDirectoryLdapServer extends AbstractLdapServer {

	private final Logger logger = LoggerFactory.getLogger(getClass());
  
  @NotNull
  private final Authenticator authenticator;

  public ActiveDirectoryLdapServer(@NotNull Authenticator authenticator) {
    this.authenticator = authenticator;
  }

	@Override
	public void changePassword(String username, String oldPassword,
			String newPassword) throws LdapException, UserNotFoundException {
		logger.debug("changePassword({},,)", username);
    String dn = lookupDn(username);
		Connection conn = connectionFactory.getConnection();
		try {
			conn.open();
      
			ModifyOperation modify = new ModifyOperation(conn);
			// remove password attribute and add new
            // http://msdn.microsoft.com/en-us/library/cc223248.aspx
			modify.execute(
					new ModifyRequest(
							lookupDn(username),
//              new AttributeModification(REPLACE, new UnicodePwdAttribute("newPassword")
              new AttributeModification(REMOVE, new LdapAttribute("unicodePwd", encodePassword(oldPassword))),
              new AttributeModification(ADD, new LdapAttribute("unicodePwd", encodePassword(newPassword))) 
//							new AttributeModification(AttributeModificationType.REMOVE, new UnicodePwdAttribute(oldPassword)), 
//							new AttributeModification(AttributeModificationType.ADD, new UnicodePwdAttribute(newPassword))
					)
			);
    } catch (LdapException e) {
      logger.error("Error changing password", e);
      throw e;
    } finally {
			conn.close();
		}
	}
	
	protected byte[] encodePassword(String password) {
		String quotedPassword = "\"" + password + "\"";
		try {
			return quotedPassword.getBytes("UTF-16LE");
		} catch(UnsupportedEncodingException ex) {
			throw new PasswordManagerException("UnsupportedEncodingException changing password.",ex);
		}
	}
}
