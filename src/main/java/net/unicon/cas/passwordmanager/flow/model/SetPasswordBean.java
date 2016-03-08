package net.unicon.cas.passwordmanager.flow.model;

import java.io.Serializable;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Size;

/**
 *
 * @author Harvey McQueen <hmcqueen at gmail.com>
 */
public class SetPasswordBean implements Serializable {
  
  private static final long serialVersionUID = 1L;

  /**
   * This will be set by the on-enter from the flowScope so that it can be used to validate the password
   */
  private String username = null;
  @NotNull
  @Size(min = 1, message = "pm.form.newPassword.required")
  private String newPassword;
  @NotNull
  @Size(min = 1, message = "pm.form.confirmNewPassword.required")
  private String confirmNewPassword;

  public String getNewPassword() {
    return newPassword;
  }

  public void setNewPassword(String newPassword) {
    this.newPassword = newPassword;
  }

  public String getConfirmNewPassword() {
    return confirmNewPassword;
  }

  public void setConfirmNewPassword(String confirmNewPassword) {
    this.confirmNewPassword = confirmNewPassword;
  }

  public String getUsername() {
    return username;
  }

  public void setUsername(String username) {
    this.username = username;
  }
}
