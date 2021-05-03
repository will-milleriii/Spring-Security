package com.SpringSecurity.SpringSecurity.Security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import java.security.Permission;
import java.util.concurrent.TimeUnit;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
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
//                .csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
//                .and()
                .authorizeRequests()
                .antMatchers("/", "index", "/css/*", "/js/*").permitAll()
                .antMatchers("/api/**").hasRole(UserRoles.STUDENT.name())
//                .antMatchers(HttpMethod.DELETE, "/management/api/**").hasAuthority(Permissions.COURSE_WRITE.getPermissions()) //order of antMatchers matters
//                .antMatchers(HttpMethod.POST, "/management/api/**").hasAuthority(Permissions.COURSE_WRITE.getPermissions())
//                .antMatchers(HttpMethod.PUT, "/management/api/**").hasAuthority(Permissions.COURSE_WRITE.getPermissions())
//                .antMatchers("/management/api/**").hasAnyRole(UserRoles.ADMIN.name(), UserRoles.ADMINTRAINEE.name())
                .anyRequest()
                .authenticated()
                .and()
                //.httpBasic(); // TODO -- using basic authentication (CANNOT LOGOUT OF BASIC AUTH ****)
                .formLogin() //switching from basic auth to form login
                .loginPage("/login").permitAll()
                .defaultSuccessUrl("/courses", true)
                .and()
                .rememberMe().tokenValiditySeconds((int)TimeUnit.DAYS.toSeconds(2)).key("SecureKey") //set remember me sessions to 2 day's time
                .and()
                .logout()
                    .logoutUrl("/logout")
                    .logoutRequestMatcher(new AntPathRequestMatcher("/logout", "GET"))
                    .clearAuthentication(true)
                    .invalidateHttpSession(true)
                    .deleteCookies("JSESSIONID", "remember-me")
                    .logoutSuccessUrl("/login");
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
