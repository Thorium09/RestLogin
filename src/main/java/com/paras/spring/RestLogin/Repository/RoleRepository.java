package com.paras.spring.RestLogin.Repository;

import java.util.Optional;

import com.paras.spring.RestLogin.Models.ERole;
import com.paras.spring.RestLogin.Models.Role;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;



@Repository
public interface RoleRepository extends JpaRepository<Role, Long> {
    Optional<Role> findByName(ERole name);
}
