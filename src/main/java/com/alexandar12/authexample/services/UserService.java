package com.alexandar12.authexample.services;

import java.util.List;

import com.alexandar12.authexample.models.CustomUser;
import com.alexandar12.authexample.models.Role;

public interface UserService {
	
	CustomUser saveUser(CustomUser user);
	Role saveRole(Role role);
	void addRoleToUser(String username, String roleName);
	CustomUser getCustomUser(String username);
	List<CustomUser> getUsers();
}
