package com.SpringSecurity.SpringSecurity.Security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

import java.security.Permission;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private final PasswordEncoder passwordEncoder;

    @Autowired
    public SecurityConfig(PasswordEncoder passwordEncoder){
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .csrf().disable()//TODO temporarily disabled but will enable later
                .authorizeRequests()
                .antMatchers("/", "index", "/css/*", "/js/*").permitAll()
                .antMatchers("/api/**").hasRole(UserRoles.STUDENT.name())
                .antMatchers(HttpMethod.DELETE, "/management/api/**").hasAuthority(Permissions.COURSE_WRITE.name())
                .antMatchers(HttpMethod.POST, "/management/api/**").hasAuthority(Permissions.COURSE_WRITE.name())
                .antMatchers(HttpMethod.PUT, "/management/api/**").hasAuthority(Permissions.COURSE_WRITE.name())
                .antMatchers("/management/api/**").hasAnyRole(UserRoles.ADMIN.name(), UserRoles.ADMINTRAINEE.name())
                .anyRequest()
                .authenticated()
                .and()
                .httpBasic(); // TODO -- using basic authentication (CANNOT LOGOUT OF BASIC AUTH ****)
    }

    @Override
    @Bean
    protected UserDetailsService userDetailsService() {
        UserDetails user = User.builder()
                .username("bingo")
                .password(passwordEncoder.encode("password"))
                //.roles(UserRoles.STUDENT.name()) //ROLE_STUDENT (how spring security will see the role)
                .authorities(UserRoles.STUDENT.getGrantedAuthority()) //changed roles to authorities to show difference in syntax/execution
                .build();

        UserDetails admin = User.builder()
                .username("flare")
                .password(passwordEncoder.encode("password123"))
                //.roles(UserRoles.ADMIN.name())
                .authorities(UserRoles.ADMIN.getGrantedAuthority())
                .build();

        UserDetails adminTrainee = User.builder()
                .username("midnight")
                .password(passwordEncoder.encode("123password"))
                //.roles(UserRoles.ADMINTRAINEE.name())
                .authorities(UserRoles.ADMINTRAINEE.getGrantedAuthority())
                .build();

        return new InMemoryUserDetailsManager(
                user,
                admin,
                adminTrainee
        );
    }
}
