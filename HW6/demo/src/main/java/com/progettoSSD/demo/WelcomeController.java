package com.progettoSSD.demo;

import java.util.Map;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class WelcomeController {

    @GetMapping("/welcome")
    public String welcome(@AuthenticationPrincipal OAuth2User principal, Model model) {
        // Check if the user is authenticated
        if (principal == null) {
            return "redirect:/login"; // If not authenticated, redirect to login page
        }

            // Retrieve user information from OAuth2User
            Map<String, Object> attributes = principal.getAttributes();

            // Add attributes to the model so they can be accessed in Thymeleaf
            model.addAttribute("name", attributes.get("name"));
            model.addAttribute("email", attributes.get("email"));
            model.addAttribute("given_name", attributes.get("given_name"));
            model.addAttribute("family_name", attributes.get("family_name"));

            return "welcome"; // This will render the welcome.html page
    }
}
