package com.progettoSSD.demo;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.SecurityFilterChain;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Configuration
public class SecurityConfig {

    private final AuthenticationManager ldapAuthenticationManager;

    public SecurityConfig(AuthenticationManager ldapAuthenticationManager) {
        this.ldapAuthenticationManager = ldapAuthenticationManager;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(authorizeRequests -> 
                authorizeRequests
                    .requestMatchers("/", "/login**" ,"/ldap**","/error").permitAll() // Permetti l'accesso alla home page e risorse statiche
                    .anyRequest().authenticated() // Richiedi l'autenticazione per qualsiasi altra richiesta
            )
            .oauth2Login(oauth2Login -> 
                oauth2Login
                    .defaultSuccessUrl("/welcome", true) // Reindirizza alla home page dopo il login
                    .failureUrl("/error") // Reindirizza alla pagina di errore in caso di fallimento
                    .successHandler((HttpServletRequest request, HttpServletResponse response, Authentication authentication) -> { // Success handler personalizzato
                        // Reindirizza l'utente a /welcome dopo il login con successo
                        response.sendRedirect("/welcome");
                    })
            )
            .logout(logout -> 
                logout
                    .logoutSuccessUrl("https://localhost:8080/realms/ProgettoSSD/protocol/openid-connect/logout?post_logout_redirect_uri=https://localhost:8443/")
                    .logoutSuccessUrl("https://accounts.google.com/logout") // Dopo il logout, reindirizza alla home page
                    .invalidateHttpSession(true) // Invalida la sessione
                    .clearAuthentication(true) // Cancella i dettagli dell'autenticazione
                    .deleteCookies("JSESSIONID") // Elimina i cookie della sessione
            )
            .formLogin(formLogin -> 
                formLogin
                    .loginPage("/ldap") // Specifica /ldap come pagina di login
                    .defaultSuccessUrl("/welcome-ldap", true) // Reindirizza a /welcome dopo il login
                    .failureUrl("/welcome-ldap") // Reindirizza in caso di fallimento
            )
            .authenticationManager(ldapAuthenticationManager) // Usa il gestore di autenticazione LDAP
            ;
            
        return http.build();
    }

    
}
