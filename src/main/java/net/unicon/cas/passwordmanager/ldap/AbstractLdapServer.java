package net.unicon.cas.passwordmanager.ldap;

import java.util.ArrayList;
import java.util.List;

import java.util.Map;
import javax.validation.constraints.NotNull;
import net.unicon.cas.passwordmanager.PasswordManagerException;
import net.unicon.cas.passwordmanager.UserNotFoundException;

import net.unicon.cas.passwordmanager.flow.SecurityChallenge;
import net.unicon.cas.passwordmanager.flow.SecurityQuestion;

import org.jasig.cas.authentication.handler.NoOpPrincipalNameTransformer;
import org.jasig.cas.authentication.handler.PrincipalNameTransformer;
import org.ldaptive.*;
import org.ldaptive.auth.DnResolver;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * 
 * @author Harvey McQueen <hmcqueen at gmail.com>
 */
public abstract class AbstractLdapServer implements LdapServer {

  private final Logger logger = LoggerFactory.getLogger(AbstractLdapServer.class);

  /**
   * A map of answer attributes (key) to question attributes (value)
   */
  protected Map<String, String> customQuestions;
  /**
   * A map of answer attributes (key) to question text (value)
   */
  protected Map<String, String> defaultQuestions;
  /**
   * The password attribute to use
   */
  protected String passwordAttr;
  /**
   * A description of the server.
   * 
   * It is used in some logging
   */
  protected String description;

  /**
   * The ldaptive {@link ConnectionFactory} to use for ldap operations
   * 
   * Note: this is not used in {@link #lookupDn(java.lang.String)}.  It is configured separately.
   */
  @NotNull
  protected ConnectionFactory connectionFactory;

  /**
   * The ldaptive {@link DnResolver} to use for looking up distinguished names from usernames
   */
  @NotNull
  protected DnResolver dnResolver;

  /**
   * Transforms the username before looking up with the {@link #dnResolver}.
   * 
   * The default is {@link NoOpPrincipalNameTransformer}
   */
  @NotNull
  private PrincipalNameTransformer principalNameTransformer = new NoOpPrincipalNameTransformer();

  /**
   * Uses a {@link DnResolver} to find the distinguished name for the user identified by the
   * provided username.
   * 
   * Before attempting the resolution, the username will be transformed with the configured
   * {@link #principalNameTransformer}
   * 
   * @param username
   * @return the Distinguished Name for the username provided
   * @throws LdapException
   * @throws UserNotFoundException thrown if a dn isn't found for the provided username
   */
  protected String lookupDn(String username) throws LdapException, UserNotFoundException {
    String dn = dnResolver.resolve(getPrincipalNameTransformer().transform(username));
    if (dn == null) {
      throw new UserNotFoundException();
    }
    return dn;
  }
  
  /**
   * Performs a {@link ModifyOperation} with the provided {@link AttributeModification}s on the entry found via the username.
   * 
   * The distinguished name for the provided username is retrieved via {@link #lookupDn(java.lang.String)}
   *
   * @param username
   * @param modifications
   * @throws LdapException
   * @throws UserNotFoundException thrown if {@link #lookupDn(java.lang.String)} fails to find a user with the provided username
   */
  @Override
  public void ldapModify(String username, AttributeModification... modifications) throws LdapException, UserNotFoundException {
    Connection conn = connectionFactory.getConnection();
    try {
      conn.open();
      ModifyOperation modify = new ModifyOperation(conn);
      modify.execute(
              new ModifyRequest(
                      lookupDn(username),
                      modifications
              )
      );
    } finally {
      conn.close();
    }
  }

  /**
   * Retrieves the {@link SecurityChallenge} for the specified username
   * 
   * This will be composed of the default questions provided in the configuration as well as
   * custom questions. 
   * 
   * The distinguished name for the provided username is retrieved via {@link #lookupDn(java.lang.String)}
   * 
   * @param username
   * @return 
   * @throws LdapException
   * @throws UserNotFoundException thrown if {@link #lookupDn(java.lang.String)} fails to find a user with the provided username
   */
  @Override
  public SecurityChallenge getUserSecurityChallenge(String username) throws LdapException, UserNotFoundException {
    List<SecurityQuestion> questions = new ArrayList<>(defaultQuestions.size() + customQuestions.size());
    // Load up default questions
    for (Map.Entry<String, String> entry : defaultQuestions.entrySet()) {
      questions.add(new SecurityQuestion(entry.getValue(), entry.getKey()));
    }

    if (customQuestions.size() > 0) {
      Connection conn = connectionFactory.getConnection();
      try {
        conn.open();
        SearchOperation search = new SearchOperation(conn);

        SearchResult result = search.execute(SearchRequest.newObjectScopeSearchRequest(lookupDn(username), customQuestions.values().toArray(new String[customQuestions.size()]))).getResult();
        LdapEntry ldapEntry = result.getEntry();
        for (Map.Entry<String, String> entry : customQuestions.entrySet()) {
          LdapAttribute attribute = ldapEntry.getAttribute(entry.getValue());
          if (attribute == null) {
            throw new PasswordManagerException("Custom Security Challenge attribute " + entry.getValue() + " not found for " + username);
          }
          questions.add(new SecurityQuestion(ldapEntry.getAttribute(entry.getValue()).getStringValue(), entry.getKey()));
        }
      } finally {
        conn.close();
      }
    }

    return new SecurityChallenge(username, questions);
  }

  /**
   *
   * @param username
   * @param securityChallenge
   * @throws LdapException
   * @throws UserNotFoundException
   */
  @Override
  public void setUserSecurityChallenge(String username, SecurityChallenge securityChallenge) throws LdapException, UserNotFoundException {
    // need to modify a question attribute and an answer attribute for each
    // security question, hence 2 * securityQuestionAttrs.size().
//    
//    Set<AttributeModification> modifications = new HashSet<>(2 * customQuestions.size());
//    
//    for(SecurityQuestionBean question : questions) {
//      modifications.add(new AttributeModification(AttributeModificationType.REPLACE, new LdapAttribute(question., securityQuestion.getQuestionText())));
//      modifications.add(new AttributeModification(AttributeModificationType.REPLACE, new LdapAttribute(securityResponseAttr, securityQuestion.getResponseAttribute())));
//    }
//		
//		for(int i = 0; i < questions.size(); i++) {
//      SecurityQuestionBean question = questions.
//			String securityQuestionAttr = securityQuestionAttrs.get(i);
//			String securityResponseAttr = securityResponseAttrs.get(i);
//			SecurityQuestion securityQuestion = securityQuestions.get(i);
//			
//			modifications[2*i] = ;
//			modifications[2*i+1] = ;
//		}
//		
//		ldapModify(username, modifications);
  }
  
  /**
   * Encodes the password for the ldap server
   * 
   * Can be overridden for different ldap server types.
   * 
   * @param password
   * @return the encoded password
   */
  protected byte[] encodePassword(String password) {
    return password.getBytes();
  }

  /**
   * Set the password for the username via {@link #ldapModify(java.lang.String, org.ldaptive.AttributeModification...)}
   * 
   * Uses a {@link AttributeModification} with {@link AttributeModificationType#REPLACE} using {@link #getPasswordAttr()} and {@link #encodePassword(java.lang.String)}
   *
   * @param username
   * @param password
   * @throws LdapException
   * @throws UserNotFoundException thrown if {@link #lookupDn(java.lang.String)} fails to find a user with the provided username
   */
  @Override
  public void setPassword(String username, String password) throws LdapException, UserNotFoundException {
    ldapModify(username, new AttributeModification(AttributeModificationType.REPLACE, new LdapAttribute(getPasswordAttr(), encodePassword(password))));
  }
  /**
   * Verifies an attribute value with a {@link CompareOperation}
   * 
   * The distinguished name of the entry to check is retrieved via {@link #lookupDn(java.lang.String)}
   * 
   * @param username 
   * @param name attribute name to check the value of
   * @param value value to verify
   * @return true if the value matches, false otherwise.
   * @throws LdapException 
   * @throws UserNotFoundException thrown if {@link #lookupDn(java.lang.String)} fails to find a user with the provided username
   */
  @Override
  public boolean verifyAttribute(String username, String name, String value) throws LdapException, UserNotFoundException {
    Connection conn = connectionFactory.getConnection();
    try {
      conn.open();
      CompareOperation compare = new CompareOperation(conn);
      return compare.execute(
              new CompareRequest(lookupDn(username), new LdapAttribute(name, value))).getResult();
    } finally {
      conn.close();
    }
  }

  public ConnectionFactory getConnectionFactory() {
    return connectionFactory;
  }

  public void setConnectionFactory(ConnectionFactory connectionFactory) {
    this.connectionFactory = connectionFactory;
  }

  public DnResolver getDnResolver() {
    return dnResolver;
  }

  public void setDnResolver(DnResolver dnResolver) {
    this.dnResolver = dnResolver;
  }

  public Map<String, String> getCustomQuestions() {
    return customQuestions;
  }

  public void setCustomQuestions(Map<String, String> customQuestions) {
    this.customQuestions = customQuestions;
  }

  public Map<String, String> getDefaultQuestions() {
    return defaultQuestions;
  }

  public void setDefaultQuestions(Map<String, String> defaultQuestions) {
    this.defaultQuestions = defaultQuestions;
  }

  public String getPasswordAttr() {
    return passwordAttr;
  }

  public void setPasswordAttr(String passwordAttr) {
    this.passwordAttr = passwordAttr;
  }

  @Override
  public String getDescription() {
    return description;
  }

  public void setDescription(String description) {
    this.description = description;
  }

  protected final PrincipalNameTransformer getPrincipalNameTransformer() {
    return this.principalNameTransformer;
  }

  public void setPrincipalNameTransformer(PrincipalNameTransformer principalNameTransformer) {
    this.principalNameTransformer = principalNameTransformer;
  }
}
