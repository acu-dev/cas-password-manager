package net.unicon.cas.passwordmanager.flow;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import org.springframework.binding.message.MessageBuilder;
import org.springframework.binding.message.MessageContext;
import org.springframework.binding.validation.ValidationContext;

/**
 * <p>
 * Bean for holding the security challenge. Consists of the user's NetID and a list of
 * SecurityQuestion objects.</p>
 */
public class SecurityChallenge implements Serializable {

  private static final long serialVersionUID = 1L;

  // Instance Members.
  private final String netId;
  private final List<SecurityQuestion> questions;
  
  public SecurityChallenge(String netId, List<SecurityQuestion> questions) {

    // Assertions.
    if (netId == null) {
      String msg = "Argument 'netId' cannot be null";
      throw new IllegalArgumentException(msg);
    }
    if (questions == null) {
      String msg = "Argument 'questions' cannot be null";
      throw new IllegalArgumentException(msg);
    }
    if (questions.isEmpty()) {
      String msg = "Argument 'questions' must contain at least one element";
      throw new IllegalArgumentException(msg);
    }

    this.netId = netId;
    this.questions = Collections.unmodifiableList(questions);
  }

  public String getNetId() {
    return netId;
  }

  public List<SecurityQuestion> getQuestions() {
    return questions;
  }
  
  public void validateAnswerSecurityChallenge(ValidationContext context) {
    MessageContext messages = context.getMessageContext();
    for (int i = 0; i < questions.size(); i++) {
      SecurityQuestion q = questions.get(i);
      if (q.getAnswer() == null || q.getAnswer().trim().isEmpty()) {
        messages.addMessage(new MessageBuilder().error().source("questions["+i+"].answer")
              .code("pm.form.securityChallenge.question.required")
              .defaultText("You must answer the question")
              .build());
      }
    }
  }

}
