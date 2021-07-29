package com.alexandar12.authexample.repo;

import org.springframework.data.jpa.repository.JpaRepository;

import com.alexandar12.authexample.models.Role;

public interface RoleRepo extends JpaRepository<Role, Long> {
	Role findByName(String name);
}
