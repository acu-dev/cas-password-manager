/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package net.unicon.cas.passwordmanager.flow.model;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Size;

/**
 *
 * @author Harvey McQueen <hmcqueen at gmail.com>
 */
public class AnswerSecurityQuestionsBean implements Serializable {
  
  private static final long serialVersionUID = 1L;
  
  @NotNull(message = "pm.form.securityQuestions.required")
  @Size(min = 1, message = "pm.form.securityQuestions.required")
  private List<String> responses = new ArrayList<>();

  public List<String> getResponses() {
    return responses;
  }

  public void setResponses(List<String> responses) {
    this.responses = responses;
  }
  
}
