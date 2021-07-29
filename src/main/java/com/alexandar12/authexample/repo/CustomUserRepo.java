package com.alexandar12.authexample.repo;

import org.springframework.data.jpa.repository.JpaRepository;

import com.alexandar12.authexample.models.CustomUser;

public interface CustomUserRepo extends JpaRepository<CustomUser, Long> {
	CustomUser findByUsername(String username);
}
