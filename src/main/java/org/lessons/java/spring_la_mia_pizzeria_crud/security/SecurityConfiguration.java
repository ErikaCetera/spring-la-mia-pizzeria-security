package org.lessons.java.spring_la_mia_pizzeria_crud.security;


import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
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
SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    return http
        .authorizeHttpRequests(authz -> authz
            .requestMatchers("/home").permitAll() // Permette l'accesso libero alla homepage
            .requestMatchers("/pizze/create", "/pizze/edit/**").hasAuthority("ADMIN")
            .requestMatchers(HttpMethod.POST, "/pizze/**").hasAuthority("ADMIN")
            .requestMatchers("/offers", "/offers/**").hasAnyAuthority("USER", "ADMIN")
            .requestMatchers(HttpMethod.POST, "/offers/**").hasAuthority("ADMIN")
            .requestMatchers(HttpMethod.PUT, "/offers/**").hasAuthority("ADMIN")
            .requestMatchers(HttpMethod.DELETE, "/offers/**").hasAuthority("ADMIN")
            .requestMatchers("/ingredient", "/ingredient/**").hasAnyAuthority("USER", "ADMIN")
            .requestMatchers(HttpMethod.POST, "/ingredienti/**").hasAuthority("ADMIN")
            .requestMatchers(HttpMethod.PUT, "/ingredienti/**").hasAuthority("ADMIN")
            .requestMatchers(HttpMethod.DELETE, "/ingredienti/**").hasAuthority("ADMIN")
            .anyRequest().authenticated() // Qualsiasi altra richiesta richiede autenticazione
        )
        .formLogin(form -> form
            .loginPage("/login") // Pagina di login personalizzata
            .permitAll()
        )
        .logout(logout -> logout
            .logoutUrl("/logout")
            .logoutSuccessUrl("/")
            .invalidateHttpSession(true)
            .deleteCookies("JSESSIONID")
        )
        .exceptionHandling(ex -> ex
            .accessDeniedPage("/access-denied") // Pagina per accesso negato
        )
        .build();
}


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




