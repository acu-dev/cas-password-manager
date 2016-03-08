package net.unicon.cas.passwordmanager.service;

import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.validation.constraints.Size;
import net.unicon.cas.passwordmanager.ConstraintViolationException;
import net.unicon.cas.passwordmanager.InvalidPasswordException;


import net.unicon.cas.passwordmanager.UserLockedOutException;
import net.unicon.cas.passwordmanager.UserNotFoundException;
import net.unicon.cas.passwordmanager.ldap.LdapServer;
import net.unicon.cas.passwordmanager.flow.SecurityChallenge;
import net.unicon.cas.passwordmanager.flow.SecurityQuestion;

import org.ldaptive.LdapException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.ldap.NameNotFoundException;
import org.springframework.ldap.core.ObjectRetrievalException;

/**
 * <p>LDAP implementation of a PasswordManagerService.</p>
 * @author Drew Mazurek &lt;dmazurek@unicon.net&gt;
 *
 */
public class LdapPasswordManagerService implements PasswordManagerService {
  
  /** Pattern to find error code in exception messages. */
  // LDAP: error code 19 - 0000052D:
  private static final Pattern PATTERN = Pattern.compile(
    "LDAP: error code (\\d+) - (\\w+):");

	private final Logger logger = LoggerFactory.getLogger(LdapPasswordManagerService.class);
	@Size(min=1)
	private List<LdapServer> ldapServers;
	private PasswordManagerLockoutService lockoutService;
    private Map<String, String> defaultQuestions;
    
    

	@Override
	public SecurityChallenge getSecurityChallenge(String username) throws UserNotFoundException {
		
		for(LdapServer server : ldapServers) {
			try {
				SecurityChallenge challenge = server.getUserSecurityChallenge(username);
				if(logger.isDebugEnabled()) {
					if(challenge != null) {
						logger.debug("Successfully got security challenge for {} at {}", username, server.getDescription());
					} else {
						logger.debug("Got null security challenge for {} at {}", username, server.getDescription());
					}
				}
				return challenge;
			} catch (LdapException ex) {
				logger.error("Error finding {} in {}", username, server.getDescription());
				// ignore it... try the next server
      } catch (UserNotFoundException ex) {
				logger.debug("Didn't find {} in {}", username, server.getDescription());
				// ignore it... try the next server
      }
		}
		
		throw new UserNotFoundException("Couldn't find username " 
				+ username + " in any of provided servers.");
	}

	@Override
	public void setUserSecurityChallenge(String username,
			SecurityChallenge securityChallenge) throws LdapException {
		
		for(LdapServer server : ldapServers) {
			try {
				server.setUserSecurityChallenge(username, securityChallenge);
				logger.debug("Successfully set user security challenge for " + username + " at " + server.getDescription());
				return;
			} catch(NameNotFoundException ex) {
				logger.debug("Didn't find " + username + " in " + server.getDescription());
				// ignore it... try the next server
			} catch(ObjectRetrievalException ex) {
				logger.debug("Multiple results found for " + username);
				// ignore it... try the next server
			} catch (UserNotFoundException ex) {
                logger.debug("Didn't find {} in {}", username, server.getDescription());
				// ignore it... try the next server
            }
		}
		
		throw new NameNotFoundException("Couldn't find username " 
				+ username + " in any of provided servers.");
	}
	
//    @Override
//	public SecurityChallenge getDefaultSecurityChallenge(String username) {
//		
//		for(LdapServer ldapServer : ldapServers) {
//			try {
//				SecurityChallenge challenge = ldapServer.getDefaultSecurityChallenge(username);
//				if(logger.isDebugEnabled()) {
//					if(challenge != null) {
//						logger.debug("Successfully got default security challenge for " + username + " at " + ldapServer.getDescription());
//					} else {
//						logger.debug("Got null default security challenge for " + username + " at " + ldapServer.getDescription());
//					}
//				}
//				return challenge;
//			} catch(NameNotFoundException ex) {
//				logger.debug("Didn't find " + username + " in " + ldapServer.getDescription());
//				// ignore... we'll try another server
//			} catch(ObjectRetrievalException ex) {
//				logger.debug("Multiple results found for " + username);
//				// ignore it... try the next server
//			}
//		}
//		
//		logger.debug("Couldn't find default security questions for " + username);
//		throw new NameNotFoundException("Couldn't find username " 
//				+ username + " in any of provided servers.");
//	}

	@Override
	public void setUserPassword(String username, String password) throws UserNotFoundException {
        logger.trace("setUserPassword({},)", username);
		logger.trace("We have {} LDAP servers to look at.", ldapServers.size());
        
		for(LdapServer ldapServer : ldapServers) {
			logger.debug("Checking server {} for user {}", ldapServer.getDescription(), username);
			try {
				ldapServer.setPassword(username, password);
				logger.debug("Successfully set password for {} at {}", username, ldapServer.getDescription());
				return;
			} catch(UserNotFoundException ex) {
				logger.debug("Didn't find {} in {}", username, ldapServer.getDescription());
				// ignore... we'll try another server
			} catch(LdapException ex) {
				logger.debug("Setting password failed for {} in {}", username, ldapServer.getDescription());
				// ignore it... try the next server
			}
		}
		
		logger.debug("Couldn't set password for {}", username);
		throw new UserNotFoundException("Couldn't find username " 
				+ username + " in any of provided servers.");		
	}

	@Override
	public void changeUserPassword(String username, String oldPassword, String newPassword) throws InvalidPasswordException, UserLockedOutException, UserNotFoundException, ConstraintViolationException {
		logger.trace("changePassword({},,)", username);
		logger.trace("We have {} LDAP servers to look at.", ldapServers.size());
		// throws UserLockedOutException if this isn't allowed
		lockoutService.allowAttempt(username);
		
		for(LdapServer ldapServer : ldapServers) {
			try {
				ldapServer.changePassword(username, oldPassword, newPassword);
				logger.debug("Successfully changed password for {} at {}", username, ldapServer.getDescription());
				lockoutService.clearIncorrectAttempts(username);
				return;
			} catch(UserNotFoundException ex) {
				logger.debug("Didn't find {} in {}", username, ldapServer.getDescription());
				// ignore... we'll try another server
			} catch(LdapException ex) {
				logger.debug("Changing password failed for {} in {}", username, ldapServer.getDescription(), ex);
        switch (ex.getResultCode()) {
          case CONSTRAINT_VIOLATION:
            final Matcher matcher = PATTERN.matcher(ex.getMessage());
            if (matcher.find()) {
              switch (matcher.group(2)) {
                case "0000052D": // Tried to use an old password in violation of the rules
                  throw new ConstraintViolationException();
                case "00000056": // Wrong oldPassword
                  throw new InvalidPasswordException();
                default:
                  break;
              }
            }
            throw new ConstraintViolationException();
          default:
            logger.warn("Changing password failed for {} in {}", username, ldapServer.getDescription(), ex);
            // ignore it... try the next server
            // We should probably add specific handling for errors.  I don't like the idea of ignoring them.
            break;
        }
			}
		}
		
		lockoutService.registerIncorrectAttempt(username);
		logger.debug("Couldn't find server for {} or bad password.", username);
		throw new UserNotFoundException("Couldn't find username " 
				+ username + " in any of provided servers or bad password.");	
	}

	public void setLdapServers(List<LdapServer> ldapServers) {
		this.ldapServers = ldapServers;
	}

	public void setLockoutService(PasswordManagerLockoutService lockoutService) {
		this.lockoutService = lockoutService;
	}

  @Override
  public void setDefaultSecurityQuestions(Map<String, String> questions) {
    this.defaultQuestions = questions;
  }

  @Override
  public boolean verifySecurityQuestion(String username, SecurityQuestion question) {
    for (LdapServer ldapServer : ldapServers) {
      try {
        return ldapServer.verifyAttribute(username, question.getResponseAttribute(), question.getAnswer());
      } catch (UserNotFoundException ex) {
      } catch (LdapException ex) {
      }
    }
    return false;
  }
}
