package org.lessons.java.spring_la_mia_pizzeria_crud.security;


import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfiguration {
    
@Bean
public WebSecurityCustomizer webSecurityCustomizer() {
    return (web) -> web.ignoring().requestMatchers("/");
}


@Bean
public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    return http
        .authorizeHttpRequests(authz -> authz
            // Accesso libero alla homepage
            .requestMatchers("/home").permitAll()

            // Solo gli ADMIN possono eseguire operazioni di modifica
            .requestMatchers(HttpMethod.POST, "/pizze/**").hasAuthority("ADMIN")
            .requestMatchers(HttpMethod.PUT, "/pizze/**").hasAuthority("ADMIN")
            .requestMatchers(HttpMethod.DELETE, "/pizze/**").hasAuthority("ADMIN")

            .requestMatchers(HttpMethod.POST, "/offers/**").hasAuthority("ADMIN")
            .requestMatchers(HttpMethod.PUT, "/offers/**").hasAuthority("ADMIN")
            .requestMatchers(HttpMethod.DELETE, "/offers/**").hasAuthority("ADMIN")

            .requestMatchers(HttpMethod.POST, "/ingredient/**").hasAuthority("ADMIN")
            .requestMatchers(HttpMethod.PUT, "/ingredient/**").hasAuthority("ADMIN")
            .requestMatchers(HttpMethod.DELETE, "/ingredient/**").hasAuthority("ADMIN")

            // Gli USER possono accedere alle risorse senza modificarle
            .requestMatchers("/pizze/**", "/offers/**", "/ingredient/**").hasAnyAuthority("USER", "ADMIN")

            .anyRequest().authenticated()
        )
        .formLogin(Customizer.withDefaults())
        .logout(logout -> logout
            .logoutUrl("/logout")
            .logoutSuccessUrl("/")
            .invalidateHttpSession(true)
            .deleteCookies("JSESSIONID")
        )
        .exceptionHandling(ex -> ex.accessDeniedPage("/access-denied"))
        .build();
    }

@Bean
// @SuppressWarnings("deprecation")
DaoAuthenticationProvider authenticationProvider(){
    DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
    authProvider.setUserDetailsService(userDetailService());
    authProvider.setPasswordEncoder(passwordEncoder());
    return authProvider;
}

@Bean
DatabaseUserDetailService userDetailService(){
    return new DatabaseUserDetailService();
}


@Bean
PasswordEncoder passwordEncoder(){
    return PasswordEncoderFactories.createDelegatingPasswordEncoder();

}

}




