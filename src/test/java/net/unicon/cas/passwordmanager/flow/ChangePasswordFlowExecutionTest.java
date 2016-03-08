package net.unicon.cas.passwordmanager.flow;

import net.unicon.cas.passwordmanager.ConstraintViolationException;
import net.unicon.cas.passwordmanager.UserLockedOutException;
import net.unicon.cas.passwordmanager.UserNotFoundException;
import net.unicon.cas.passwordmanager.flow.model.ChangePasswordBean;
import net.unicon.cas.passwordmanager.flow.validator.ChangePasswordBeanValidator;
import net.unicon.cas.passwordmanager.service.PasswordManagerLockoutService;
import net.unicon.cas.passwordmanager.service.PasswordManagerService;
import org.junit.Test;
import org.springframework.binding.message.MessageContext;
import org.springframework.webflow.config.FlowDefinitionResource;
import org.springframework.webflow.config.FlowDefinitionResourceFactory;
import org.springframework.webflow.core.collection.LocalAttributeMap;
import org.springframework.webflow.core.collection.MutableAttributeMap;
import org.springframework.webflow.execution.Event;
import org.springframework.webflow.execution.RequestContext;
import org.springframework.webflow.test.MockExternalContext;
import org.springframework.webflow.test.MockFlowBuilderContext;
import org.springframework.webflow.test.execution.AbstractXmlFlowExecutionTests;

import static net.unicon.cas.passwordmanager.flow.RecaptchaValidationAction.RECAPTCHA_POST_PARAMETER;
import static org.mockito.Mockito.*;

/**
 *
 * @author Harvey McQueen <hmcqueen at gmail.com>
 */
public class ChangePasswordFlowExecutionTest extends AbstractXmlFlowExecutionTests {

  private MessageContext messageContext;
  private RecaptchaValidationAction recaptchaValidationAction;
	
	private static final String GOOD_RESPONSE = "good";
	private static final String BAD_RESPONSE = "bad";

  @Override
  protected FlowDefinitionResource getResource(FlowDefinitionResourceFactory resourceFactory) {
    return resourceFactory.createFileResource("src/main/webapp/WEB-INF/pm/changePassword.xml");
  }

  @Override
  protected FlowDefinitionResource[] getModelResources(FlowDefinitionResourceFactory resourceFactory) {
    return new FlowDefinitionResource[]{
      resourceFactory.createFileResource("src/main/webapp/WEB-INF/pm/common.xml")
    };
  }

  @Override
  protected void configureFlowBuilderContext(MockFlowBuilderContext builderContext) {
    try {
      messageContext = mock(MessageContext.class);
      builderContext.registerBean("messageContext", messageContext);
      
      PasswordManagerLockoutService lockoutService = mock(PasswordManagerLockoutService.class);
      doThrow(UserLockedOutException.class).when(lockoutService).allowAttempt("locked");
      builderContext.registerBean("lockoutService", lockoutService);
      
      // Set up recaptcha
      recaptchaValidationAction = mock(RecaptchaValidationAction.class);
      when(recaptchaValidationAction.doExecute(any(RequestContext.class))).thenReturn(new Event(recaptchaValidationAction, "yes"));
//      doReturn(new Event(recaptchaValidationAction, "yes")).when(recaptchaValidationAction).validateCaptcha(messageContext, GOOD_RESPONSE);
//      doReturn(new Event(recaptchaValidationAction, "no")).when(recaptchaValidationAction).validateCaptcha(messageContext, BAD_RESPONSE);
//			when(recaptchaValidationAction.validateCaptchaResponse(GOOD_RESPONSE)).thenReturn(Boolean.TRUE);
//			when(recaptchaValidationAction.validateCaptchaResponse(BAD_RESPONSE)).thenReturn(Boolean.FALSE);
      builderContext.registerBean("recaptchaValidationAction", recaptchaValidationAction);
      
      // Set Up action
      PasswordManagerService pmService = mock(PasswordManagerService.class);
      doThrow(UserLockedOutException.class).when(pmService).changeUserPassword("locked", "old", "new");
//      doThrow(InvalidPasswordException.class).when(pmService).changeUserPassword("test", "bad", "new");
      doThrow(UserNotFoundException.class).when(pmService).changeUserPassword("invalid", "old", "new");
      
      doThrow(UserNotFoundException.class).when(pmService).setUserPassword("invalid", "new");
      
      ChangePasswordBeanValidator validator = new ChangePasswordBeanValidator();
      validator.setPasswordRegex(".*");
      builderContext.registerBean("changePasswordBeanValidator", validator);
      
      ProcessChangePasswordAction changePasswordAction = new ProcessChangePasswordAction();
      changePasswordAction.setPasswordManagerService(pmService);
      
      builderContext.registerBean("processChangePasswordAction", changePasswordAction);
    } catch (Exception ex) { }
  }

  @Test
  public void testStartChangePasswordFlow() {
    MutableAttributeMap input = new LocalAttributeMap();
    input.put("forced", false);

    MockExternalContext context = new MockExternalContext();
    startFlow(input, context);

    assertCurrentStateEquals("viewChangePassword");
  }
  
  public void testChangePasswordFlowReturn() {
    setCurrentState("viewChangePassword");
    
    MockExternalContext context = new MockExternalContext();
    context.setEventId("return");
    resumeFlow(context);
    
    assertFlowExecutionEnded();
  }

  public void testChangePasswordFlowSubmit() throws Exception {
    
    setCurrentState("viewChangePassword");
    
    getFlowScope().put("changePasswordBean", createChangePasswordBean());
//    getFlowScope().put("messageContext", messageContext);
    
    MockExternalContext context = new MockExternalContext();
    context.getMockRequestParameterMap().put(RECAPTCHA_POST_PARAMETER, GOOD_RESPONSE);
    context.setEventId("submit");
    
    resumeFlow(context);

    assertCurrentStateEquals("passwordChanged");
  }

  public void testChangePasswordFlowSubmitBad() {
    setCurrentState("viewChangePassword");

    ChangePasswordBean bean = createChangePasswordBean();
    bean.setUsername("invalid");
    getFlowScope().put("changePasswordBean", bean);

    getFlowScope().put("messageContext", messageContext);
    
    MockExternalContext context = new MockExternalContext();
    context.getMockRequestParameterMap().put(RECAPTCHA_POST_PARAMETER, GOOD_RESPONSE);
    
    context.setEventId("submit");
    resumeFlow(context);

    assertCurrentStateEquals("viewChangePassword");
  }
  
  public void testChangePasswordFlowSubmitBadCaptcha() throws Exception {
    setCurrentState("viewChangePassword");
    
    RecaptchaValidationAction recaptchaValidationAction = mock(RecaptchaValidationAction.class);
    when(recaptchaValidationAction.doExecute(any(RequestContext.class))).thenReturn(new Event(recaptchaValidationAction, "no"));
    getFlowScope().put("recaptchaValidationAction", recaptchaValidationAction);

    getFlowScope().put("changePasswordBean", createChangePasswordBean());

    getFlowScope().put("messageContext", messageContext);
    
    MockExternalContext context = new MockExternalContext();
    context.getMockRequestParameterMap().put(RECAPTCHA_POST_PARAMETER, BAD_RESPONSE);
    
    context.setEventId("submit");
    resumeFlow(context);

    assertCurrentStateEquals("viewChangePassword");
  }
  
  public void testPasswordChangedContinue() {
    setCurrentState("passwordChanged");
    
    MockExternalContext context = new MockExternalContext();
    context.setEventId("continue");
    resumeFlow(context);
    
    assertFlowExecutionEnded();
  }

  public void testChangePasswordFlowSubmitLocked() {
    setCurrentState("viewChangePassword");

    getFlowScope().put("username", null);

    ChangePasswordBean bean = createChangePasswordBean();
    bean.setUsername("locked");
    getFlowScope().put("changePasswordBean", bean);

    MockExternalContext context = new MockExternalContext();
    context.getMockRequestParameterMap().put(RECAPTCHA_POST_PARAMETER, GOOD_RESPONSE);
		
    context.setEventId("submit");
    resumeFlow(context);

    assertCurrentStateEquals("lockedOut");
  }

  private ChangePasswordBean createChangePasswordBean() {
    ChangePasswordBean bean = new ChangePasswordBean();
    bean.setUsername("test");
    bean.setOldPassword("old");
    bean.setNewPassword("new");
    bean.setConfirmNewPassword("new");
    return bean;
  }

}
