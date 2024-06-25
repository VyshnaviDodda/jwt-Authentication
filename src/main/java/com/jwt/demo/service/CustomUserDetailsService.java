package com.jwt.demo.service;

import java.util.Arrays;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.jwt.demo.DTO.UserDTO;
import com.jwt.demo.model.DAOUser;
import com.jwt.demo.repo.UserRepository;

@Service
public class CustomUserDetailsService implements UserDetailsService {

    public UserRepository userRepo;
    private PasswordEncoder bcryptEncoder;
    private JavaMailSender javaMailSender;

    @Autowired
    public CustomUserDetailsService(UserRepository userRepo, PasswordEncoder bcryptEncoder, JavaMailSender javaMailSender) {
        this.userRepo = userRepo;
        this.bcryptEncoder = bcryptEncoder;
        this.javaMailSender = javaMailSender;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        DAOUser user = userRepo.findByEmail(username);
        if (user == null) {
            throw new UsernameNotFoundException("User not found with the name " + username);
        }

        List<SimpleGrantedAuthority> roles = Arrays.asList(new SimpleGrantedAuthority(user.getRole()));
        System.out.println(user.getEmail());
        System.out.println(user.getPassword());
        System.out.println(user.getRole());
        return new User(user.getEmail(), user.getPassword(), roles);
    }

    public DAOUser saveUser(UserDTO user) {
        DAOUser newUser = new DAOUser();
        newUser.setUsername(user.getUsername());
        newUser.setPassword(bcryptEncoder.encode(user.getPassword()));
        newUser.setEmail(user.getEmail());
        newUser.setRole(user.getRole());
        return userRepo.save(newUser);
    }

    public String generateOtp(DAOUser user) 
    {
        try 
        {
            int randomPIN = (int) (Math.random() * 9000) + 1000;
            user.setOTP(randomPIN);
            userRepo.save(user);
            SimpleMailMessage msg = new SimpleMailMessage();
            msg.setFrom("narasimhulubayanaboyina@gmail.com");
            msg.setTo(user.getEmail());
            msg.setSubject("Welcome To Two Factor Authentication");
            msg.setText("Hello \n\n" + "Your Login OTP: " + randomPIN + ". Please verify. \n\n" + "Regards \n" + "ABC");

            javaMailSender.send(msg);
            return "success";
        } 
        catch (Exception e) 
        {
            e.printStackTrace();
            return "error";
        }
    }
    
    
   
    
    
}
