package com.jwt.demo.DTO;

import com.jwt.demo.model.DAOUser;

public class AuthenticationResponse {
    private final String token;
    private final DAOUser user;

    public AuthenticationResponse(String token, DAOUser user) {
        this.token = token;
        this.user = user;
    }

	public String getToken() {
		return token;
	}

	public DAOUser getUser() {
		return user;
	}
}

