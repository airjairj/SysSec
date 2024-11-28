package com.progettoSSD.demo;

import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Controller
public class LoginController {

    @GetMapping("/ldap")
    public String ldapLogin() {
        return "ldap"; // Nome del template per la pagina di login LDAP
    }

    @GetMapping("/login")
    public String loginPage() {
        return "index"; // Nome del template per la pagina di login
    }

    @GetMapping("/error")
    public String errorPage() {
        return "error"; // Nome del template per la pagina di errore
    }

    @GetMapping("/logout")
    public String logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        if (authentication != null) {
            new SecurityContextLogoutHandler().logout(request, response, authentication);
        }
        return "redirect:/"; // Reindirizza alla home page
    }    
}
