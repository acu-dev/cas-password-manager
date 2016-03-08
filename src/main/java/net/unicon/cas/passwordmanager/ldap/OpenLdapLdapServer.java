package net.unicon.cas.passwordmanager.ldap;

import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import net.unicon.cas.passwordmanager.UserNotFoundException;

import org.apache.commons.codec.binary.Base64;
import org.ldaptive.Connection;
import org.ldaptive.Credential;
import org.ldaptive.LdapException;
import org.ldaptive.Response;
import org.ldaptive.ResultCode;
import org.ldaptive.extended.PasswordModifyOperation;
import org.ldaptive.extended.PasswordModifyRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class OpenLdapLdapServer extends AbstractLdapServer {

	private final Logger logger = LoggerFactory.getLogger(OpenLdapLdapServer.class);
	
	private String encryptionAlgorithm;
	
  @Override
	protected byte[] encodePassword(String password) {
		String passwordText = null;
		
		if(encryptionAlgorithm != null && !encryptionAlgorithm.isEmpty()) {
			String encryptedPassword = encrypt(password);
			passwordText = "{" + encryptionAlgorithm + "}" + encryptedPassword;
		} else {
			passwordText = password;
		}
		
		return passwordText.getBytes();
	}
	
	private String encrypt(String plainText) {
		MessageDigest md = null;
		try {
			md = MessageDigest.getInstance(encryptionAlgorithm);
			md.update(plainText.getBytes("UTF-8"));
		} catch(NoSuchAlgorithmException ex) {
			logger.error("No such algorithm: {}", encryptionAlgorithm);
			throw new RuntimeException("No such algorithm: " + encryptionAlgorithm,ex);
		} catch(UnsupportedEncodingException ex) {
			logger.error("Unsupported encoding: UTF-8");
			throw new RuntimeException("Unsupported encoding: UTF-8",ex);
		}
		byte bytes[] = md.digest();
		return Base64.encodeBase64String(bytes);
	}

	public void setEncryptionAlgorithm(String encryptionAlgorithm) {
		this.encryptionAlgorithm = encryptionAlgorithm;
	}

    // TODO: test this.  Does it need encryption stuff?
	@Override
	public void changePassword(String username, String oldPassword,
			String newPassword) throws LdapException, UserNotFoundException {
		Connection conn = connectionFactory.getConnection();
		try {
			conn.open();
			PasswordModifyOperation modify = new PasswordModifyOperation(conn);
			Response<Credential> response = modify.execute(new PasswordModifyRequest(lookupDn(username), new Credential(oldPassword), new Credential(newPassword)));
			if (response.getResultCode() != ResultCode.SUCCESS) {
				// TODO: throw an exception?
			}
		} finally {
			conn.close();
		}
	}
}
