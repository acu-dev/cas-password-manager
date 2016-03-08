package net.unicon.cas.authentication.support;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.security.auth.login.AccountExpiredException;
import javax.security.auth.login.AccountLockedException;
import javax.security.auth.login.CredentialExpiredException;
import javax.security.auth.login.LoginException;
import javax.validation.constraints.NotNull;
import org.jasig.cas.Message;
import org.jasig.cas.authentication.AccountDisabledException;
import org.jasig.cas.authentication.AccountPasswordMustChangeException;
import org.jasig.cas.authentication.InvalidLoginLocationException;
import org.jasig.cas.authentication.InvalidLoginTimeException;
import org.jasig.cas.authentication.support.DefaultAccountStateHandler;
import org.jasig.cas.authentication.support.LdapPasswordPolicyConfiguration;
import org.ldaptive.auth.AccountState;
import org.ldaptive.auth.AuthenticationResponse;
import org.ldaptive.auth.ext.ActiveDirectoryAccountState;
import org.ldaptive.auth.ext.EDirectoryAccountState;
import org.ldaptive.auth.ext.PasswordExpirationAccountState;
import org.ldaptive.control.PasswordPolicyControl;

/**
 *
 * @author Harvey McQueen <hmcqueen at gmail.com>
 */
public class PmAccountStateHandler extends DefaultAccountStateHandler {

  /**
   * Default map of account state error to CAS authentication exception.
   */
  private static final Map<AccountState.Error, LoginException> DEFAULT_ERROR_MAP = new HashMap<>();

  static {
    DEFAULT_ERROR_MAP.put(ActiveDirectoryAccountState.Error.ACCOUNT_DISABLED, new AccountDisabledException());
    DEFAULT_ERROR_MAP.put(ActiveDirectoryAccountState.Error.ACCOUNT_LOCKED_OUT, new AccountLockedException());
    DEFAULT_ERROR_MAP.put(ActiveDirectoryAccountState.Error.INVALID_LOGON_HOURS, new InvalidLoginTimeException());
    DEFAULT_ERROR_MAP.put(ActiveDirectoryAccountState.Error.INVALID_WORKSTATION, new InvalidLoginLocationException());
    DEFAULT_ERROR_MAP.put(ActiveDirectoryAccountState.Error.PASSWORD_MUST_CHANGE, new AccountPasswordMustChangeException());
    DEFAULT_ERROR_MAP.put(ActiveDirectoryAccountState.Error.PASSWORD_EXPIRED, new CredentialExpiredException());
    DEFAULT_ERROR_MAP.put(ActiveDirectoryAccountState.Error.ACCOUNT_EXPIRED, new AccountExpiredException());
    DEFAULT_ERROR_MAP.put(EDirectoryAccountState.Error.ACCOUNT_EXPIRED, new AccountExpiredException());
    DEFAULT_ERROR_MAP.put(EDirectoryAccountState.Error.LOGIN_LOCKOUT, new AccountLockedException());
    DEFAULT_ERROR_MAP.put(EDirectoryAccountState.Error.LOGIN_TIME_LIMITED, new InvalidLoginTimeException());
    DEFAULT_ERROR_MAP.put(EDirectoryAccountState.Error.PASSWORD_EXPIRED, new CredentialExpiredException());
    DEFAULT_ERROR_MAP.put(PasswordExpirationAccountState.Error.PASSWORD_EXPIRED, new CredentialExpiredException());
    DEFAULT_ERROR_MAP.put(PasswordPolicyControl.Error.ACCOUNT_LOCKED, new AccountLockedException());
    DEFAULT_ERROR_MAP.put(PasswordPolicyControl.Error.PASSWORD_EXPIRED, new CredentialExpiredException());
  }

  /**
   * Map of account state error to CAS authentication exception.
   */
  @NotNull
  private Map<AccountState.Error, LoginException> errorMap = DEFAULT_ERROR_MAP;

  /**
   * Sets the map of account state error to CAS authentication exception.
   *
   * @param errorMap Map of account state errors to CAS authentication exceptions
   */
  public void setErrorMap(Map<AccountState.Error, LoginException> errorMap) {
    this.errorMap = errorMap;
  }

  public final Map<AccountState.Error, LoginException> getErrorMap() {
    return Collections.unmodifiableMap(this.errorMap);
  }

  @Override
  protected void handleError(
          final AccountState.Error error,
          final AuthenticationResponse response,
          final LdapPasswordPolicyConfiguration configuration,
          final List<Message> messages)
          throws LoginException {

    logger.debug("Handling {}", error);
    final LoginException ex = errorMap.get(error);
    if (ex != null) {
      throw ex;
    }
    logger.debug("No LDAP error mapping defined for {}", error);
  }

}
