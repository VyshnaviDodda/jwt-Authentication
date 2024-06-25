package com.jwt.demo.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import com.jwt.demo.DTO.AuthenticationRequest;
import com.jwt.demo.DTO.AuthenticationResponse;
import com.jwt.demo.DTO.OtpRequest;
import com.jwt.demo.DTO.UserDTO;
import com.jwt.demo.model.DAOUser;
import com.jwt.demo.repo.UserRepository;
import com.jwt.demo.service.CustomUserDetailsService;
import com.jwt.demo.service.JwtUtil;


import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.Cookie;
import org.springframework.security.core.Authentication;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@RestController
public class AuthenticationController {

    private static final Logger logger = LoggerFactory.getLogger(AuthenticationController.class);

    private AuthenticationManager authenticationManager;
    private CustomUserDetailsService userDetailsService;
    private JwtUtil jwtTokenUtil;
    private UserRepository userRepository;

    @Autowired
    public AuthenticationController(AuthenticationManager authenticationManager,
                                    CustomUserDetailsService userDetailsService, 
                                    JwtUtil jwtTokenUtil,
                                    UserRepository userRepository) {
        this.authenticationManager = authenticationManager;
        this.userDetailsService = userDetailsService;
        this.jwtTokenUtil = jwtTokenUtil;
        this.userRepository = userRepository;
    }

    @PostMapping("/authenticate")
    public ResponseEntity<?> createAuthenticationToken(@RequestBody AuthenticationRequest authenticationRequest,
                                                       HttpServletResponse response) throws Exception {
        logger.info("Authentication request received for user: {}", authenticationRequest.getEmail());
        try {
            authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(
                    authenticationRequest.getEmail(), authenticationRequest.getPassword()));
        } catch (DisabledException e) {
            logger.error("User is disabled: {}", authenticationRequest.getEmail(), e);
            throw new Exception("USER_DISABLED", e);
        } catch (BadCredentialsException e) {
            logger.error("Invalid credentials for user: {}", authenticationRequest.getEmail(), e);
            throw new Exception("INVALID_CREDENTIALS", e);
        }
        
        final UserDetails userDetails = userDetailsService.loadUserByUsername(authenticationRequest.getEmail());
        final String token = jwtTokenUtil.generateToken(userDetails);
        
        // Save token into cookies
        Cookie cookie = new Cookie("JWT-TOKEN", token);
        cookie.setPath("/");
        cookie.setHttpOnly(true); // HTTP Only flag
        cookie.setMaxAge(60 * 20); // 20 minutes expiration
        response.addCookie(cookie);
        
        
        
        // Retrieve user details from the repository
        DAOUser user = userRepository.findByEmail(authenticationRequest.getEmail());
        
        // Create a response object that includes both the token and user details
        AuthenticationResponse authenticationResponse = new AuthenticationResponse(token, user);
        
        logger.info("Authentication successful for user: {}", authenticationRequest.getEmail());
        return ResponseEntity.ok(authenticationResponse);
    }

    @RequestMapping(value = "/register", method = RequestMethod.POST)
    public ResponseEntity<?> saveUser(@RequestBody UserDTO user) throws Exception {
        logger.info("Register request received for user: {}", user.getEmail());
        ResponseEntity<?> responseEntity = ResponseEntity.ok(userDetailsService.saveUser(user));
        logger.info("Registration successful for user: {}", user.getEmail());
        return responseEntity;
    }
    
    @GetMapping("/userDetails")
    public ResponseEntity<?> getUserDetails() {
        logger.info("Fetching user details for authenticated user");
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication != null && authentication.isAuthenticated()) {
            String username = authentication.getName();
            DAOUser user = userRepository.findByEmail(username);
            if (user != null) {
                logger.info("User details found for user: {}", username);
                return ResponseEntity.ok(user);
            } else {
                logger.warn("User details not found for user: {}", username);
                return ResponseEntity.status(HttpStatus.NOT_FOUND).body("User not found");
            }
        } else {
            logger.warn("No authenticated user found");
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("User is not logged in");
        }
    }

    @GetMapping("/logout")
    public ResponseEntity<?> logout(HttpServletRequest request, HttpServletResponse response) {
        logger.info("Logout request received");
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication != null && authentication.isAuthenticated()) {
            logger.info("User is authenticated, proceeding with logout");
            SecurityContextHolder.clearContext();
            
            if (request.getSession(false) != null) {
                request.getSession(false).invalidate();
                logger.info("Session invalidated");
            }

            Cookie[] cookies = request.getCookies();
            if (cookies != null) {
                for (Cookie cookie : cookies) {
                    cookie.setMaxAge(0);
                    cookie.setValue(null);
                    cookie.setPath("/");
                    response.addCookie(cookie);
                }
                logger.info("Cookies cleared");
            }
            logger.info("Logout successful");
            return ResponseEntity.ok("Logout successful");
        } else {
            logger.warn("User is not authenticated");
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("User is not logged in");
        }
    }
    
    
  
    
}
