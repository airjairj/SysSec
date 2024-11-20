package com.gruppo.servlet;

import java.io.IOException;
import java.io.PrintWriter;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.bettercloud.vault.VaultException;


public class VaultServlet extends HttpServlet {

    private VaultService vaultService;

    private static final String PERCORSO_SECRET = "secret/data/"; // DEBUG PERCORSO SECRET

    @Override
    public void init() throws ServletException {
        try {
            // Inizializza VaultService durante l'inizializzazione della servlet
            vaultService = new VaultService();
        } catch (VaultException e) {
            throw new ServletException("Error initializing Vault", e);
        }
    }

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        // Ottieni il parametro "action" per determinare se aggiungere o leggere un segreto
        String action = request.getParameter("action");
        // Ottieni la chiave e il valore del segreto (se esistono)
        String secretKey = request.getParameter("key");
        String secretValue = request.getParameter("value");

        response.setContentType("text/html");
        PrintWriter out = response.getWriter();

        if ("signup".equalsIgnoreCase(action)) {
            if (secretKey != null && secretValue != null) {
                // Aggiungi il segreto con la chiave e il valore specificati
                String secretPath = PERCORSO_SECRET+secretKey; // PERCORSO SECRET
                String checkValue = vaultService.getSecret(secretPath, secretKey);
                if (checkValue != null && checkValue.equals(secretValue)) {
                    out.println("Username not available");
                }
                else
                {
                    boolean success = vaultService.addSecret(secretPath, secretKey, secretValue);

                    if (success) {
                        out.println("Sign up succsessful!");
                    } else {
                        out.println("Failed to sign up!");
                    }
                }
            } else {
                out.println("Missing username or password!");
            }
        } else if ("login".equalsIgnoreCase(action)) {
            if (secretKey != null && secretValue != null) {
                // Leggi il segreto con la chiave specificata
                String secretPath = PERCORSO_SECRET+secretKey; // PERCORSO SECRET
                String storedSecretValue = vaultService.getSecret(secretPath, secretKey);

                if (storedSecretValue != null && storedSecretValue.equals(secretValue)) {
                    out.println("Login successful!");
                } else {
                    out.println("Invalid username or password!");
                }
            } else {
                out.println("Missing username or password!");
            }
        } else {
            out.println("Invalid action parameter!");
        }
    }
}