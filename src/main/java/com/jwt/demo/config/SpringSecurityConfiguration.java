package com.jwt.demo.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.jwt.demo.service.CustomUserDetailsService;

import jakarta.servlet.http.HttpServletResponse;
@Configuration
@EnableWebSecurity
public class SpringSecurityConfiguration {

    private final CustomUserDetailsService userDetailsService;
    private final PasswordEncoder passwordEncoder;
    private final CustomJwtAuthenticationFilter customJwtAuthenticationFilter;

    @Autowired
    public SpringSecurityConfiguration(CustomUserDetailsService userDetailsService, PasswordEncoder passwordEncoder,
			CustomJwtAuthenticationFilter customJwtAuthenticationFilter) {
		super();
		this.userDetailsService = userDetailsService;
		this.passwordEncoder = passwordEncoder;
		this.customJwtAuthenticationFilter = customJwtAuthenticationFilter;
	}

    @Autowired
    public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userDetailsService).passwordEncoder(passwordEncoder);
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.csrf().disable()
                .authorizeRequests()
                .requestMatchers("/api/admin").hasRole("ADMIN")
                .requestMatchers("/api/user").hasAnyRole("ADMIN", "USER")
                .requestMatchers("/authenticate", "/register").permitAll()
            
                .anyRequest().authenticated()
                .and().httpBasic().and().exceptionHandling()
                .and().sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and().cors();

        http.addFilterBefore(customJwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);
        
        // Configure logout
        http.logout()
                .logoutUrl("/logout") // URL where the logout will be performed
                .logoutSuccessHandler((request, response, authentication) -> {
                    response.setStatus(HttpServletResponse.SC_OK);
                    response.getWriter().write("Logout successful"); // Send a response on successful logout
                    response.getWriter().flush();
                })
                .deleteCookies("JWT-TOKEN") // Clear specific cookies upon logout if necessary
                .invalidateHttpSession(true) // Invalidate any existing HTTP session
                .clearAuthentication(true); // Clear the authentication details
        
        return http.build();
    }
}
