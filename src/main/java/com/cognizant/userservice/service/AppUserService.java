package com.cognizant.userservice.service;

import java.util.List;

import com.cognizant.userservice.model.AppUser;
import com.cognizant.userservice.model.Role;

public interface AppUserService {
	AppUser saveUser(AppUser user);

	Role saveRole(Role role);

	void addRoleToUser(String username, String name);

	AppUser getUser(String username);

	List<AppUser> getUsers();
}
