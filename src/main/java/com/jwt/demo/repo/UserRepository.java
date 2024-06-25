package com.jwt.demo.repo;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.jwt.demo.model.DAOUser;

@Repository
public interface UserRepository extends JpaRepository<DAOUser, Long>
{

	DAOUser findByEmail(String username);

}
