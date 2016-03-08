package net.unicon.cas.passwordmanager.flow;

import com.fasterxml.jackson.core.JsonFactory;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import javax.validation.constraints.Min;
import javax.validation.constraints.NotNull;


import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.InputStream;
import org.springframework.binding.message.MessageBuilder;
import org.springframework.binding.message.MessageContext;
import org.springframework.webflow.action.AbstractAction;
import org.springframework.webflow.execution.Event;
import org.springframework.webflow.execution.RequestContext;
import org.springframework.webflow.execution.RequestContextHolder;

import static java.net.URLEncoder.encode;

public class RecaptchaValidationAction extends AbstractAction {

	public static final String RECAPTCHA_POST_PARAMETER = "g-recaptcha-response";
	private static final String DEFAULT_VALIDATE_URL = "https://www.google.com/recaptcha/api/siteverify";
	private static final String ENCODING = "UTF-8";

	private final Logger logger = LoggerFactory.getLogger(RecaptchaValidationAction.class);

	@NotNull
	private String secret;
	@NotNull
	private String siteKey;
	@NotNull
	private String validateUrl = DEFAULT_VALIDATE_URL;
	
	private void genericError(MessageContext context) {
    addErrorMessage(context, "cas.pm.recaptcha.error", "There was an error validating the captcha.  If this error continues, please contact your system administrator.");
	}
  
  private void addErrorMessage(MessageContext context, String code, String defaultMessage) {
    context.addMessage(new MessageBuilder().error().source("recaptcha").code(code).defaultText(defaultMessage).build());
  }

	public void setSecret(String secret) {
		this.secret = secret;
	}
	
	public void setSiteKey(String siteKey) {
		this.siteKey = siteKey;
	}
	
	public String getSiteKey() {
		return this.siteKey;
	}

	public void setValidateUrl(String validateUrl) {
		this.validateUrl = validateUrl;
	}

  @Override
  protected Event doExecute(RequestContext context) throws Exception {
    String captchaResponse = context.getRequestParameters().get(RECAPTCHA_POST_PARAMETER);
    
    if (captchaResponse == null || captchaResponse.trim().isEmpty()) {
      addErrorMessage(context.getMessageContext(), "pm.form.recaptcha.required", "The captcha is required.");
      return no();
    }
		
    return validateCaptcha(context.getMessageContext(), captchaResponse);
  }
  
  protected Event validateCaptcha(MessageContext context, String captchaResponse) {
    String urlString = null;
		InputStreamReader reader = null;
		try {
			urlString = validateUrl + "?secret=" + encode(secret, ENCODING) + "&response=" + encode(captchaResponse, ENCODING);
			URL url = new URL(urlString);
			HttpURLConnection connection = (HttpURLConnection) url.openConnection();
			connection.setConnectTimeout(500);
			connection.setReadTimeout(500);
			InputStream stream = connection.getInputStream();
			reader = new InputStreamReader(stream);
			
			// Convert to a JSON object to print data
			JsonParser jp = new JsonParser(); //from gson
			JsonElement root = jp.parse(reader); //convert the input stream to a json element
			if (root.isJsonObject()) {
				JsonObject verifyResponse = root.getAsJsonObject();
				JsonElement success = verifyResponse.get("success");
				if (success.isJsonPrimitive() && success.getAsBoolean()) {
          return yes();
				}
				JsonArray errorCodes = verifyResponse.getAsJsonArray("error-codes");
				for (JsonElement el : errorCodes) {
          String error = el.getAsString();
          addErrorMessage(context, "cas.pm.recaptcha."+error, "There was an error checking the captcha: " + error);
          return error();
				}
			}
		} catch (MalformedURLException ex) {
			logger.error("There was an error with the url ({}).  You might want to verify that the validateUrl is correctly configured.", urlString, ex);
			genericError(context);
      return error(ex);
		} catch (UnsupportedEncodingException ex) {
			logger.error("The encoding for the url parameters failed.", ex);
			genericError(context);
      return error(ex);
		} catch (IOException ex) {
			logger.error("An error occurred while retrieving the InputStream", ex);
			genericError(context);
      return error(ex);
		} finally {
			if (reader != null) {
				try {
					reader.close();
				} catch (IOException ex) { }
			}
		}
		
		return no();
  }

}
