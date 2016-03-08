package net.unicon.cas.passwordmanager.flow.validator;

import net.unicon.cas.passwordmanager.flow.model.ChangePasswordBean;
import net.unicon.cas.passwordmanager.flow.model.SetPasswordBean;
import org.springframework.binding.message.MessageBuilder;
import org.springframework.binding.message.MessageContext;
import org.springframework.binding.validation.ValidationContext;

public class SetPasswordBeanValidator {

	// default regex accepts any password
	private String passwordRegex = ".*";

	public void validateViewSetPassword(SetPasswordBean setPasswordBean,
			ValidationContext context) {
		
		MessageContext messageContext = context.getMessageContext();
    String username = setPasswordBean.getUsername();
		String newPassword = setPasswordBean.getNewPassword();
		String confirmNewPassword = setPasswordBean.getConfirmNewPassword();
		
    // The bean validation will catch if the password is null or empty
    if (newPassword.toLowerCase().contains(username.toLowerCase())) {
      messageContext.addMessage(new MessageBuilder().error().source("newPassword")
              .code("pm.form.newPassword.username")
              .defaultText("The new password must not contain your username")
              .build());
    }
    if(!newPassword.matches(passwordRegex)) {
      messageContext.addMessage(new MessageBuilder().error().source("newPassword")
          .code("cas.pm.newpassword.weak")
          .defaultText("The password is too weak")
          .build());
    } else if(confirmNewPassword == null || !confirmNewPassword.equals(newPassword)) {
      messageContext.addMessage(new MessageBuilder().error().source("confirmNewPassword")
          .code("cas.pm.newpassword.mismatch")
          .defaultText("The passwords do not match")
          .build());
    }
	}
	
	public void setPasswordRegex(String passwordRegex) {
		this.passwordRegex = passwordRegex;
	}
}
