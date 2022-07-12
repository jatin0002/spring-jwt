package com.cognizant.userservice.serviceImpl;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import javax.transaction.Transactional;

import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.cognizant.userservice.model.AppUser;
import com.cognizant.userservice.model.Role;
import com.cognizant.userservice.repository.RoleRepository;
import com.cognizant.userservice.repository.UserRepository;
import com.cognizant.userservice.service.AppUserService;

import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Service
@AllArgsConstructor
@Transactional
@Slf4j
public class AppUserServiceImpl implements AppUserService, UserDetailsService {

	private final UserRepository userRepository;
	private final RoleRepository roleRepository;
	private final PasswordEncoder encoder;

	@Override
	public AppUser saveUser(AppUser user) {
		log.info("Saving new user to the database");
		user.setPassword(encoder.encode(user.getPassword()));
		return userRepository.save(user);
	}

	@Override
	public Role saveRole(Role role) {
		log.info("Saving new role {} to the database", role.getName());
		return roleRepository.save(role);
	}

	@Override
	public void addRoleToUser(String username, String roleName) {
		log.info("Adding role {} to user {} ", roleName, username);
		AppUser user = userRepository.findByUsername(username);
		Role role = roleRepository.findByName(roleName);
		user.getRoles().add(role);
	}

	@Override
	public AppUser getUser(String username) {
		log.info("Fetching user {} ", username);
		return userRepository.findByUsername(username);
	}

	@Override
	public List<AppUser> getUsers() {
		log.info("Fetching all users");
		return userRepository.findAll();
	}

	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		AppUser user = userRepository.findByUsername(username);
		if (user == null) {
			log.info("User not found int the database");
			throw new UsernameNotFoundException("User not found int the database");
		} else {
			log.info("User found int the database");
		}
		Collection<SimpleGrantedAuthority> authorities = new ArrayList<>();
		user.getRoles().forEach(role -> {
			authorities.add(new SimpleGrantedAuthority(role.getName()));
		});
		return new org.springframework.security.core.userdetails.User(user.getUsername(), user.getPassword(),
				authorities);
	}

}
