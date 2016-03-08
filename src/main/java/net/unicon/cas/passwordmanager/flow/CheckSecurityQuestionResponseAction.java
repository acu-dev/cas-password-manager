package net.unicon.cas.passwordmanager.flow;

import java.util.List;
import net.unicon.cas.passwordmanager.flow.model.AnswerSecurityQuestionsBean;

import net.unicon.cas.passwordmanager.service.PasswordManagerLockoutService;
import net.unicon.cas.passwordmanager.service.PasswordManagerService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.binding.message.MessageBuilder;
import org.springframework.webflow.action.AbstractAction;
import org.springframework.webflow.execution.Event;
import org.springframework.webflow.execution.RequestContext;

/**
 * <p>
 * Action for checking the responses to users' security questions.</p>
 */
public class CheckSecurityQuestionResponseAction extends AbstractAction {

  private static final Logger logger = LoggerFactory.getLogger(CheckSecurityQuestionResponseAction.class);
  public static final String RESPONSE_PARAMETER_PREFIX = "response";
  
  private PasswordManagerLockoutService lockoutService;
  private PasswordManagerService pmService;

  @Override
  protected Event doExecute(RequestContext context) throws Exception {

    SecurityChallenge challenge = (SecurityChallenge) context.getFlowScope().getRequired("securityChallenge");
    String username = context.getFlowScope().getRequiredString("username");
    List<SecurityQuestion> questions = challenge.getQuestions();
    for (int i = 0; i < questions.size(); i++) {
      if (logger.isTraceEnabled()) {
        logger.trace("pmService.verifySecurityQuestionAnswer({}, {}, <hidden>) -> {}", username, questions.get(i), pmService.verifySecurityQuestion(username, questions.get(i)));
      }
      if (!pmService.verifySecurityQuestion(username, questions.get(i))) {
        lockoutService.registerIncorrectAttempt(username);
        context.getMessageContext().addMessage(new MessageBuilder().error()
                .code("pm.form.securityQuestion.incorrect")
                .defaultText("You have answered a question incorrectly. Please try again.")
                .build());
        return error();
      }
    }

    return success();

  }

  public void setLockoutService(PasswordManagerLockoutService lockoutService) {
    this.lockoutService = lockoutService;
  }

  public void setPasswordManagerService(PasswordManagerService pmService) {
    this.pmService = pmService;
  }

}
