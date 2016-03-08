package net.unicon.cas.passwordmanager.flow.model;

import java.io.Serializable;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Size;
import javax.validation.groups.Default;

public class ChangePasswordBean implements Serializable {

  private static final long serialVersionUID = 1L;

  /**
   * The username.
   */
  @NotNull
  @Size(min = 1, message = "pm.form.netid.required")
  private String username;
  /**
   * The password.
   */
  @NotNull
  @Size(min = 1, message = "pm.form.oldPassword.required")
  private String oldPassword;
  /**
   * The password.
   */
  @NotNull
  @Size(min = 1, message = "pm.form.newPassword.required")
  private String newPassword;
  /**
   * The password.
   */
  @NotNull
  @Size(min = 1, message = "pm.form.confirmNewPassword.required")
  private String confirmNewPassword;

  public String getUsername() {
    return username;
  }

  public void setUsername(String username) {
    this.username = username;
  }

  public String getOldPassword() {
    return oldPassword;
  }

  public void setOldPassword(String oldPassword) {
    this.oldPassword = oldPassword;
  }

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
}
