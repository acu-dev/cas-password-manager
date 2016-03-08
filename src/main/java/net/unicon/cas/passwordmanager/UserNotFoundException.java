/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

package net.unicon.cas.passwordmanager;

/**
 *
 * @author Harvey McQueen <hmcqueen at gmail.com>
 */
public class UserNotFoundException extends Exception {

	private static final long serialVersionUID = 1L;

	public UserNotFoundException() {
		super();
	}
	
	public UserNotFoundException(String s) { 
		super(s);
	}
	
	public UserNotFoundException(String s, Throwable t) {
		super(s, t);
	}
}
