package net.unicon.cas.passwordmanager.flow;

import net.unicon.cas.passwordmanager.ConstraintViolationException;
import net.unicon.cas.passwordmanager.InvalidPasswordException;
import net.unicon.cas.passwordmanager.UserLockedOutException;
import net.unicon.cas.passwordmanager.UserNotFoundException;
import net.unicon.cas.passwordmanager.flow.model.ChangePasswordBean;
import net.unicon.cas.passwordmanager.flow.model.SetPasswordBean;
import net.unicon.cas.passwordmanager.service.PasswordManagerService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.binding.message.MessageBuilder;
import org.springframework.binding.message.MessageContext;
import org.springframework.webflow.action.MultiAction;
import org.springframework.webflow.execution.Event;
import org.springframework.webflow.execution.RequestContext;

/**
 * <p>Changes the user's password.</p>
 */
public class ProcessChangePasswordAction extends MultiAction {

	private final Logger logger = LoggerFactory.getLogger(getClass());
	private PasswordManagerService passwordManagerService;

  public Event changePassword(RequestContext context) throws Exception {
    logger.debug("changePassword");
    String flowUsername = context.getFlowScope().getString("username");
    ChangePasswordBean bean = (ChangePasswordBean) context.getFlowScope().getRequired("changePasswordBean");
    if (bean == null) {
      logger.warn("changePasswordBean is null.");
      return error();
    }
    
    // prefer a username found in the flow scope to one found in the bean
    String username = flowUsername != null ? flowUsername : bean.getUsername();

    if (username == null) {
      context.getMessageContext().addMessage(new MessageBuilder().error().source("username")
              .code("pm.form.netid.required")
              .defaultText("You must enter your username")
              .build());
      logger.debug("Username not found in flowscope or changePasswordBean.");
      return error();
    }

    try {
      passwordManagerService.changeUserPassword(username, bean.getOldPassword(), bean.getNewPassword());
    } catch (InvalidPasswordException ex) {
      context.getMessageContext().addMessage(new MessageBuilder().error().source("oldPassword")
              .code("pm.form.password.old.invalid")
              .defaultText("Username/password combination incorrect")
              .build());
      logger.debug("InvalidPasswordException changing password for user.");
      return error(ex);
    } catch (UserNotFoundException ex) {
      context.getMessageContext().addMessage(new MessageBuilder().error().source("oldPassword")
              .code("pm.form.password.old.invalid")
              .defaultText("Username/password combination incorrect")
              .build());
      logger.debug("UserNotFoundException changing password for user {}", username);
      return error(ex);
    } catch (ConstraintViolationException ex) {
      context.getMessageContext().addMessage(new MessageBuilder().error().source("newPassword")
              .code("pm.form.password.new.constraint")
              .defaultText("Your new password does not meet required specifications.")
              .build());
      logger.debug("ConstraintViolationException changing password for user {}", username, ex);
      return error(ex);
    } catch (UserLockedOutException ex) {
      throw ex;
    } catch (Exception ex) {
      logger.error("An unexpected error occurred while trying to change the password for '{}'", username, ex);
      context.getMessageContext().addMessage(new MessageBuilder().error()
              .code("pm.form.error.unknown")
              .defaultText("An unexpected error occurred.")
              .build());
      return error(ex);
    }

    return success();
  }
	
	public Event setPassword(RequestContext context) throws Exception {
    String username = context.getFlowScope().getRequiredString("username");
    SetPasswordBean bean = (SetPasswordBean) context.getFlowScope().getRequired("setPasswordBean");
		try {
      // The password is validated by the ChangePasswordBeanValidator.validateViewSetPassword method
			passwordManagerService.setUserPassword(username, bean.getNewPassword());
		} catch(UserNotFoundException ex) {
			logger.error("Error setting user's password.",ex);
			return error(ex);
		}
		
		return success();
	}
	
//	public boolean changePassword(String username, String oldPassword, 
//			String newPassword) throws UserLockedOutException, UserNotFoundException {
//		
//		try {
//			passwordManagerService.changeUserPassword(username, oldPassword, newPassword);
//		} catch(UserLockedOutException ex) {
//			logger.error("Exception changing user's password.");
//			return false;
//		} catch (UserNotFoundException ex) {
//      logger.error("Exception changing user's password.");
//      return false;
//    } catch (ConstraintViolationException ex) {
//      logger.error("Exception changing user's password.");
//      return false;
//    }
//		return true;
//	}

	public void setPasswordManagerService(
			PasswordManagerService passwordManagerService) {
		this.passwordManagerService = passwordManagerService;
	}

}
