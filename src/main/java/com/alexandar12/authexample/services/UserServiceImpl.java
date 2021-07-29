package com.alexandar12.authexample.services;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.alexandar12.authexample.models.CustomUser;
import com.alexandar12.authexample.models.Role;
import com.alexandar12.authexample.repo.CustomUserRepo;
import com.alexandar12.authexample.repo.RoleRepo;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
@Transactional
public class UserServiceImpl implements UserService, UserDetailsService {
	
	private final CustomUserRepo customUserRepo;
	private final RoleRepo roleRepo;
	private final PasswordEncoder passwordEncoder;

	@Override
	public CustomUser saveUser(CustomUser user) {
		user.setPassword(passwordEncoder.encode(user.getPassword()));
		return customUserRepo.save(user);
	}

	@Override
	public Role saveRole(Role role) {
		return roleRepo.save(role);
	}

	@Override
	public void addRoleToUser(String username, String roleName) {
		CustomUser user = customUserRepo.findByUsername(username);
		Role role = roleRepo.findByName(roleName);
		user.getRoles().add(role);
		
	}

	@Override
	public CustomUser getCustomUser(String username) {
		return customUserRepo.findByUsername(username);
	}

	@Override
	public List<CustomUser> getUsers() {
		return customUserRepo.findAll()	;
	}

	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		CustomUser user = customUserRepo.findByUsername(username);
		if (user == null) {
			throw new UsernameNotFoundException("User not found in database.");
		}
		
		Collection<SimpleGrantedAuthority> authorities = new ArrayList<>();
		user.getRoles().forEach(role -> {
			authorities.add(new SimpleGrantedAuthority(role.getName()));
		});
		
		return new org.springframework.security.core.userdetails.User(user.getUsername(), user.getPassword(), authorities);
	}
	
}
