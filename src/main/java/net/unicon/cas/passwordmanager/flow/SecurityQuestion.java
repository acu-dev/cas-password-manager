package net.unicon.cas.passwordmanager.flow;

import java.io.Serializable;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Size;

/**
 * <p>
 * Bean for holding a user security question and answer. Includes a method for validating
 * responses.</p>
 */
public class SecurityQuestion implements Serializable {

  private static final long serialVersionUID = 1L;
  public static final String DATE_REGEX = "^(0?[1-9]|1[012])/(0?[1-9]|[12][0-9]|3[01])/(19|20)\\d\\d$";
  public static final String DATE_FORMAT = "MM/dd/yyyy";

  // Instance Members.
  private String questionText;
  private String responseAttribute;
  
  @NotNull(message = "pm.form.securityQuestion.required")
  @Size(min = 1, message = "pm.form.securityQuestion.required")
  private String answer = "";

  public SecurityQuestion() {
  }

  public SecurityQuestion(String questionText, String responseAttribute) {

    // Assertions.
    if (questionText == null) {
      String msg = "Argument 'questionText' cannot be null";
      throw new IllegalArgumentException(msg);
    }
    if (responseAttribute == null) {
      String msg = "Argument 'responseText' cannot be null";
      throw new IllegalArgumentException(msg);
    }

    this.questionText = questionText;
    this.responseAttribute = responseAttribute;

  }

  public String getQuestionText() {
    return questionText;
  }

  public void setQuestionText(String questionText) {
    this.questionText = questionText;
  }

  public String getResponseAttribute() {
    return responseAttribute;
  }

  public void setResponseAttribute(String responseAttribute) {
    this.responseAttribute = responseAttribute;
  }

//    public boolean validateResponse(String responseText) {
//    	if(responseText.matches(DATE_REGEX) && this.responseAttribute.matches(DATE_REGEX)) {
//    		// validate them as dates
//    		SimpleDateFormat sdf = new SimpleDateFormat(DATE_FORMAT);
//    		try {
//				Date d1 = sdf.parse(responseText);
//	    		Date d2 = sdf.parse(this.responseAttribute);
//	    		return d1.equals(d2);
//			} catch (ParseException e) {
//				// fall back to a plain text match below
//			}
//    	}
//        return this.responseAttribute.equalsIgnoreCase(responseText);
//    }

  public String getAnswer() {
    return answer;
  }

  public void setAnswer(String answer) {
    this.answer = answer;
  }
}
