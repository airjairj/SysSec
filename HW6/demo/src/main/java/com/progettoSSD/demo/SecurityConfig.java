package com.progettoSSD.demo;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(authorizeRequests -> 
                authorizeRequests
                    .requestMatchers("/", "/login**", "/webjars/**", "/css/**", "/images/**").permitAll() // Permetti l'accesso alla home page e risorse statiche
                    .anyRequest().authenticated() // Richiedi l'autenticazione per qualsiasi altra richiesta
            )
            .oauth2Login(oauth2Login -> 
                oauth2Login
                    .loginPage("/login") // Specifica una pagina di login personalizzata (opzionale)
                    .defaultSuccessUrl("/welcome", true) // Reindirizza alla home page dopo il login
                    .failureUrl("/login?error=true") // Reindirizza alla pagina di errore in caso di fallimento
            )
            .logout(logout -> 
                logout
                    .logoutSuccessUrl("https://accounts.google.com/logout") // Dopo il logout, reindirizza alla home page
                    .invalidateHttpSession(true) // Invalida la sessione
                    .clearAuthentication(true) // Cancella i dettagli dell'autenticazione
                    .deleteCookies("JSESSIONID") // Elimina i cookie della sessione
                    .addLogoutHandler((request, response, authentication) -> {
                        // Opzionale: pulizia aggiuntiva
                    })
                    .logoutSuccessHandler((request, response, authentication) -> {
                        // Reindirizza al logout del provider OAuth2
                        response.sendRedirect("https://accounts.google.com/logout");
                    })
            );
        return http.build();
    }
}
