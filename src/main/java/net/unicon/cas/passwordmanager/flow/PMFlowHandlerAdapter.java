package net.unicon.cas.passwordmanager.flow;

import java.io.IOException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.jasig.cas.web.flow.SelectiveFlowHandlerAdapter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.webflow.core.FlowException;
import org.springframework.webflow.execution.repository.NoSuchFlowExecutionException;

/**
 *
 * @author Harvey McQueen
 */
public class PMFlowHandlerAdapter extends SelectiveFlowHandlerAdapter {
  
  private final Logger logger = LoggerFactory.getLogger(PMFlowHandlerAdapter.class);

  @Override
  protected void defaultHandleException(String flowId, FlowException e, HttpServletRequest request,
			HttpServletResponse response) throws IOException {
		if (e instanceof NoSuchFlowExecutionException && flowId != null) {
			if (!response.isCommitted()) {
				if (logger.isDebugEnabled()) {
					logger.debug("Restarting a new execution of previously ended flow '" + flowId + "'");
				}
        // TODO: Add message to let the user know why they are being returned to the log-in page.
        
				// by default, attempt to restart the flow
        // Add the service parameter so the user can return to their place.
				String flowUrl = getFlowUrlHandler().createFlowDefinitionUrl(flowId, null, request);
        String service = request.getParameter("service");
        if (service != null && !service.trim().isEmpty()) {
          flowUrl += "&service=" + service;
        }
				sendRedirect(flowUrl, request, response);
			}
		} else {
			throw e;
		}
	}

}
