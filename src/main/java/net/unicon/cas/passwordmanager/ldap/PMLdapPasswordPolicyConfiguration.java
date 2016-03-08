/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

package net.unicon.cas.passwordmanager.ldap;

import org.jasig.cas.authentication.support.LdapPasswordPolicyConfiguration;
import org.springframework.webflow.execution.RequestContextHolder;


/**
 *
 * @author Harvey McQueen <hmcqueen at gmail.com>
 */
public class PMLdapPasswordPolicyConfiguration extends LdapPasswordPolicyConfiguration {

    @Override
    public String getPasswordPolicyUrl() {
      return RequestContextHolder.getRequestContext().getFlowExecutionUrl() + "&_eventId=changePassword";
    }
    
}
