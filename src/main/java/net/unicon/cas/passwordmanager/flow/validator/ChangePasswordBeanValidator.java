package net.unicon.cas.passwordmanager.flow.validator;

import net.unicon.cas.passwordmanager.flow.model.ChangePasswordBean;
import net.unicon.cas.passwordmanager.flow.model.SetPasswordBean;
import org.springframework.binding.message.MessageBuilder;
import org.springframework.binding.message.MessageContext;
import org.springframework.binding.validation.ValidationContext;

public class ChangePasswordBeanValidator {

	// default regex accepts any password
	private String passwordRegex = ".*";
	
	public void validateViewChangePassword(ChangePasswordBean changePasswordBean,
			ValidationContext context) {
		
		MessageContext messageContext = context.getMessageContext();
    String username = changePasswordBean.getUsername();
		String oldPassword = changePasswordBean.getOldPassword();
		String newPassword = changePasswordBean.getNewPassword();
		String confirmNewPassword = changePasswordBean.getConfirmNewPassword();

    // The bean validation will catch if the password is null or empty
    if (newPassword != null && !newPassword.isEmpty()) {
      if (newPassword.equals(oldPassword)) {
        messageContext.addMessage(new MessageBuilder().error().source("newPassword")
                .code("pm.form.newPassword.same")
                .defaultText("The new password must be different")
                .build());
      }
      if (newPassword.toLowerCase().contains(username.toLowerCase())) {
        messageContext.addMessage(new MessageBuilder().error().source("newPassword")
                .code("pm.form.newPassword.username")
                .defaultText("The new password must not contain your username")
                .build());
      }
      if (!newPassword.matches(passwordRegex)) {
        messageContext.addMessage(new MessageBuilder().error().source("newPassword")
                .code("pm.form.newPassword.weak")
                .defaultText("The password is too weak")
                .build());
      } else if (!confirmNewPassword.equals(newPassword)) {
        messageContext.addMessage(new MessageBuilder().error().source("confirmNewPassword")
                .code("pm.form.confirmNewPassword")
                .defaultText("The passwords do not match")
                .build());
      }
    }
	}
	
	public void setPasswordRegex(String passwordRegex) {
		this.passwordRegex = passwordRegex;
	}
}
