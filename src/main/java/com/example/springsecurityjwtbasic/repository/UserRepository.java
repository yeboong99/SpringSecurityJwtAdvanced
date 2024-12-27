package com.example.springsecurityjwtbasic.repository;

import com.example.springsecurityjwtbasic.domain.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {

    public Boolean existsByUsername(String username);

    public User findByUsername(String username);

}
