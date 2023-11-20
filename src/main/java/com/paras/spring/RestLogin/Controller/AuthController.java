package com.paras.spring.RestLogin.Controller;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;


import com.paras.spring.RestLogin.Models.ERole;
import com.paras.spring.RestLogin.Models.Role;
import com.paras.spring.RestLogin.Models.User;
import com.paras.spring.RestLogin.Payloads.JwtResponse;
import com.paras.spring.RestLogin.Payloads.LoginRequest;
import com.paras.spring.RestLogin.Payloads.MessageResponse;
import com.paras.spring.RestLogin.Payloads.SignupRequest;
import com.paras.spring.RestLogin.Repository.RoleRepository;
import com.paras.spring.RestLogin.Repository.UserRepository;
import com.paras.spring.RestLogin.Security.Jwt.JwtUtils;
import com.paras.spring.RestLogin.Service.UserDetailsImpl;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;


@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
/* Annotations that make sure and tells the system that this class is a Controller
 * where we will write our all kind of Api's
 * */
@RequestMapping("/api/auth")
/*this annotation states the common Https link of our api*/
public class AuthController {
    public AuthController() {
    }

    AuthenticationManager authenticationManager;
//    used to verify the login users name and its password from database


    UserRepository userRepository;
//  UsersRepo

    RoleRepository roleRepository;
    // Rolerepo

    PasswordEncoder encoder;
// to encode the password user typed to verify it in data base

    JwtUtils jwtUtils;
//    another class made by me

    @Autowired
    public AuthController(AuthenticationManager authenticationManager, UserRepository userRepository, RoleRepository roleRepository, PasswordEncoder encoder, JwtUtils jwtUtils) {
        this.authenticationManager = authenticationManager;
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
        this.encoder = encoder;
        this.jwtUtils = jwtUtils;
    }

    @PostMapping("/signin")
    /*this is a http post api which will Log in the user
     * where its link will be common link + /signin
     * */
    public ResponseEntity<?> authenticateUser(@Validated @RequestBody LoginRequest loginRequest) {
// authenticating the user by its username and password
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));

        SecurityContextHolder.getContext().setAuthentication(authentication);
//        this hold the status of the auth and their details as well
        String jwt = jwtUtils.generateJwtToken(authentication);
//         this will generate a jwt token with the help of username
        UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();
//        got all the details of the user
        List<String> roles = userDetails.getAuthorities().stream()
                .map(item -> item.getAuthority())
                .collect(Collectors.toList());

        return ResponseEntity.ok(new JwtResponse(jwt,
                userDetails.getId(),
                userDetails.getUsername(),
                userDetails.getEmail(),
                roles));
    }

    @PostMapping("/signup")
    /*this is a http post api which will Log in the user
     * where its link will be common link + /signup
     * */
    public ResponseEntity<?> registerUser(@Validated @RequestBody SignupRequest signUpRequest) {
        System.out.println(signUpRequest.getEmail());

        //        checking that do we already have some user under this username or not
        if (userRepository.existsByUsername(signUpRequest.getUsername())) {
            return ResponseEntity
                    .badRequest()
                    .body(new MessageResponse("Error: Username is already taken!"));
        }
//        checking that do we already have some user under this email or not
        if (userRepository.existsByEmail(signUpRequest.getEmail())) {
            return ResponseEntity
                    .badRequest()
                    .body(new MessageResponse("Error: Email is already in use!"));
        }

        // Create new user's account
        User user = new User(signUpRequest.getUsername(),
                signUpRequest.getEmail(),
                encoder.encode(signUpRequest.getPassword()));

        Set<String> strRoles = signUpRequest.getRole();
        Set<Role> roles = new HashSet<>();

        if (strRoles == null) {
//            default given role
            Role userRole = roleRepository.findByName(ERole.ROLE_USER)
                    .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
            roles.add(userRole);
        } else {
//            else giving the role mentioned with request
            strRoles.forEach(role -> {
                switch (role) {
                    case "admin" -> {
                        Role adminRole = roleRepository.findByName(ERole.ROLE_ADMIN)
                                .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                        roles.add(adminRole);
                    }
                    case "mod" -> {
                        Role modRole = roleRepository.findByName(ERole.ROLE_MODERATOR)
                                .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                        roles.add(modRole);
                    }
                    default -> {
                        Role userRole = roleRepository.findByName(ERole.ROLE_USER)
                                .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                        roles.add(userRole);
                    }
                }
            });
        }

        user.setRoles(roles);
        userRepository.save(user);

        return ResponseEntity.ok(new MessageResponse("User registered successfully!"));
    }
}
