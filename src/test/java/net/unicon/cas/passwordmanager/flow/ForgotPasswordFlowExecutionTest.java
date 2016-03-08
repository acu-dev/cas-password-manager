package net.unicon.cas.passwordmanager.flow;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import net.unicon.cas.passwordmanager.UserLockedOutException;
import net.unicon.cas.passwordmanager.UserNotFoundException;
import net.unicon.cas.passwordmanager.flow.model.AnswerSecurityQuestionsBean;
import net.unicon.cas.passwordmanager.flow.model.NetIdBean;
import net.unicon.cas.passwordmanager.flow.model.SetPasswordBean;
import net.unicon.cas.passwordmanager.service.PasswordManagerLockoutService;
import net.unicon.cas.passwordmanager.service.PasswordManagerService;
import org.springframework.binding.message.MessageContext;
import org.springframework.webflow.config.FlowDefinitionResource;
import org.springframework.webflow.config.FlowDefinitionResourceFactory;
import org.springframework.webflow.execution.Event;
import org.springframework.webflow.execution.RequestContext;
import org.springframework.webflow.test.MockExternalContext;
import org.springframework.webflow.test.MockFlowBuilderContext;
import org.springframework.webflow.test.MockParameterMap;
import org.springframework.webflow.test.execution.AbstractXmlFlowExecutionTests;

import static net.unicon.cas.passwordmanager.flow.RecaptchaValidationAction.RECAPTCHA_POST_PARAMETER;
import static org.mockito.Mockito.*;

/**
 *
 * @author Harvey McQueen <hmcqueen at gmail.com>
 */
public class ForgotPasswordFlowExecutionTest extends AbstractXmlFlowExecutionTests {

	private PasswordManagerService pmService;
	private MessageContext messageContext;

	private static final String GOOD_RESPONSE = "good";
	private static final String BAD_RESPONSE = "bad";

	@Override
	protected FlowDefinitionResource getResource(FlowDefinitionResourceFactory resourceFactory) {
		return resourceFactory.createFileResource("src/main/webapp/WEB-INF/pm/forgotPassword.xml");
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
			doThrow(UserLockedOutException.class).when(lockoutService).registerIncorrectAttempt("locked");
			builderContext.registerBean("lockoutService", lockoutService);

			// Set up recaptcha
			RecaptchaValidationAction recaptchaValidationAction = mock(RecaptchaValidationAction.class);
      when(recaptchaValidationAction.doExecute(any(RequestContext.class))).thenReturn(new Event(recaptchaValidationAction, "yes"));
//			when(recaptchaValidationAction.validateCaptchaResponse(GOOD_RESPONSE)).thenReturn(Boolean.TRUE);
//			when(recaptchaValidationAction.validateCaptchaResponse(BAD_RESPONSE)).thenReturn(Boolean.FALSE);
			builderContext.registerBean("recaptchaValidationAction", recaptchaValidationAction);

			// Set Up action
			pmService = mock(PasswordManagerService.class);
			doThrow(UserLockedOutException.class).when(pmService).changeUserPassword("locked", "old", "new");
//      doThrow(InvalidPasswordException.class).when(pmService).changeUserPassword("test", "bad", "new");
			doThrow(UserNotFoundException.class).when(pmService).changeUserPassword("invalid", "old", "new");

			doThrow(UserNotFoundException.class).when(pmService).setUserPassword("invalid", "new");

			doReturn(null).when(pmService).getSecurityChallenge("unset");
      
      SecurityChallenge goodChallenge = createSecurityChallenge("test");
			doReturn(goodChallenge).when(pmService).getSecurityChallenge("test");
			doReturn(true).when(pmService).verifySecurityQuestion("test", goodChallenge.getQuestions().get(0));
			doReturn(true).when(pmService).verifySecurityQuestion("test", goodChallenge.getQuestions().get(1));
      SecurityChallenge badChallenge = createSecurityChallenge("bad");
			doReturn(badChallenge).when(pmService).getSecurityChallenge("bad");
			doReturn(false).when(pmService).verifySecurityQuestion("bad", badChallenge.getQuestions().get(0));
			doReturn(false).when(pmService).verifySecurityQuestion("bad", badChallenge.getQuestions().get(1));
      SecurityChallenge lockedChallenge = createSecurityChallenge("locked");
			doReturn(lockedChallenge).when(pmService).getSecurityChallenge("locked");
			doReturn(false).when(pmService).verifySecurityQuestion("locked", lockedChallenge.getQuestions().get(0));
			doReturn(false).when(pmService).verifySecurityQuestion("locked", lockedChallenge.getQuestions().get(1));

			builderContext.registerBean("ldapPasswordManagerService", pmService);

			CheckSecurityQuestionResponseAction csqra = new CheckSecurityQuestionResponseAction();
			csqra.setLockoutService(lockoutService);
			csqra.setPasswordManagerService(pmService);
			builderContext.registerBean("checkSecurityQuestionResponseAction", csqra);
			
			ProcessChangePasswordAction changePasswordAction = new ProcessChangePasswordAction();
      changePasswordAction.setPasswordManagerService(pmService);
      
      builderContext.registerBean("processChangePasswordAction", changePasswordAction);
		} catch (Exception ex) {
		}
	}

	public void testStartForgotPasswordFlow() {
		MockExternalContext context = new MockExternalContext();
		startFlow(context);

		assertCurrentStateEquals("viewForgotPassword");
	}

	public void testForgotPasswordReturn() {
		setCurrentState("viewForgotPassword");

		MockExternalContext context = new MockExternalContext();
		context.setEventId("return");
		resumeFlow(context);

		assertFlowExecutionEnded();
	}

	public void testForgotPasswordSubmitBadCaptcha() throws Exception {
		setCurrentState("viewForgotPassword");
    
    RecaptchaValidationAction recaptchaValidationAction = mock(RecaptchaValidationAction.class);
    when(recaptchaValidationAction.doExecute(any(RequestContext.class))).thenReturn(new Event(recaptchaValidationAction, "no"));
    getFlowScope().put("recaptchaValidationAction", recaptchaValidationAction);

		getViewScope().put("netIdBean", new NetIdBean());

		MockExternalContext context = new MockExternalContext();
		context.getMockRequestParameterMap().put(RECAPTCHA_POST_PARAMETER, BAD_RESPONSE);

		context.setEventId("submit");
		resumeFlow(context);

		assertCurrentStateEquals("viewForgotPassword");
	}

	public void testForgotPasswordSubmitLocked() {
		setCurrentState("viewForgotPassword");

		NetIdBean netId = new NetIdBean();
		netId.setNetId("locked");
		getViewScope().put("netIdBean", netId);

		MockExternalContext context = new MockExternalContext();
		context.getMockRequestParameterMap().put(RECAPTCHA_POST_PARAMETER, GOOD_RESPONSE);

		context.setEventId("submit");
		resumeFlow(context);

		assertCurrentStateEquals("lockedOut");
	}

	public void testForgotPasswordSubmitSuccess() {
		setCurrentState("viewForgotPassword");

		NetIdBean netId = new NetIdBean();
		netId.setNetId("test");
		getViewScope().put("netIdBean", netId);

		MockExternalContext context = new MockExternalContext();
		context.getMockRequestParameterMap().put(RECAPTCHA_POST_PARAMETER, GOOD_RESPONSE);

		context.setEventId("submit");
		resumeFlow(context);

		assertNotNull(getFlowScope().get("securityChallenge"));
		assertCurrentStateEquals("answerSecurityChallenge");
	}

	public void testAnswerSecurityChallengeFailure() throws UserNotFoundException {
		setCurrentState("answerSecurityChallenge");

		getFlowScope().put("username", "bad");
		getFlowScope().put("securityChallenge", pmService.getSecurityChallenge("bad"));
		getFlowScope().put("setPasswordBean", createSetPasswordBean());

		MockExternalContext context = new MockExternalContext();

		context.setEventId("submit");
		resumeFlow(context);

		assertCurrentStateEquals("answerSecurityChallenge");
	}

	public void testAnswerSecurityChallengeSuccess() throws UserNotFoundException {
		setCurrentState("answerSecurityChallenge");

		getFlowScope().put("username", "test");
		getFlowScope().put("securityChallenge", pmService.getSecurityChallenge("test"));
		getFlowScope().put("setPasswordBean", createSetPasswordBean());

		MockExternalContext context = new MockExternalContext();

		context.setEventId("submit");
		resumeFlow(context);

		assertCurrentStateEquals("viewSetPassword");
	}

	public void testAnswerSecurityChallengeLocked() throws UserNotFoundException {
		setCurrentState("answerSecurityChallenge");

		getFlowScope().put("username", "locked");
		getFlowScope().put("securityChallenge", pmService.getSecurityChallenge("locked"));

		MockExternalContext context = new MockExternalContext();

		context.setEventId("submit");
		resumeFlow(context);

		assertCurrentStateEquals("lockedOut");
	}

	public void testSetPasswordSubmit() {
		setCurrentState("viewSetPassword");

		getFlowScope().put("username", "test");

		getFlowScope().put("setPasswordBean", createSetPasswordBean());

		getFlowScope().put("messageContext", messageContext);

		MockExternalContext context = new MockExternalContext();

		context.setEventId("submit");
		resumeFlow(context);

		assertCurrentStateEquals("passwordSet");
	}

	public void testSetPasswordFlowSubmitFailure() {
		setCurrentState("viewSetPassword");

		getFlowScope().put("username", "invalid");

		getFlowScope().put("setPasswordBean", createSetPasswordBean());

		getFlowScope().put("messageContext", messageContext);

		MockExternalContext context = new MockExternalContext();

		context.setEventId("submit");
		resumeFlow(context);

		assertCurrentStateEquals("viewSetPassword");
	}

	public void testPasswordSetContinue() {
		setCurrentState("passwordSet");

		MockExternalContext context = new MockExternalContext();

		context.setEventId("continue");
		resumeFlow(context);

		assertFlowExecutionEnded();
	}

	private SetPasswordBean createSetPasswordBean() {
		SetPasswordBean bean = new SetPasswordBean();
		bean.setNewPassword("new");
		bean.setConfirmNewPassword("new");
		return bean;
	}
  
  private SecurityChallenge createSecurityChallenge(String name) {
    List<SecurityQuestion> questions = new ArrayList<>();
    SecurityQuestion bdQuest = new SecurityQuestion("What is your birthdate?", "birthDate");
    bdQuest.setAnswer("answer1");
    SecurityQuestion mwQuest = new SecurityQuestion("What is your magic word?", "magicWord");
    mwQuest.setAnswer("answer2");
    questions.add(bdQuest);
    questions.add(mwQuest);
    SecurityChallenge sc = new SecurityChallenge(name, questions);
    return sc;
  }

}
