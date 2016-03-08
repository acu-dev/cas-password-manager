package net.unicon.cas.passwordmanager.flow.model;

import java.io.Serializable;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Size;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

public class NetIdBean implements Serializable {

  private final Log logger = LogFactory.getLog(this.getClass());
	private static final long serialVersionUID = 1L;
  @NotNull
  @Size(min = 1, message = "pm.form.netid.required")
	private String netId;

	public String getNetId() {
		return netId;
	}

	public void setNetId(String netId) {
		this.netId = netId;
	}
  
}
