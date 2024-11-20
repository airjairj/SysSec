package com.gruppo.servlet;

import java.io.IOException;
import java.io.PrintWriter;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class LDAPServlet extends HttpServlet {

    private LDAPService ldapService;

    @Override
    public void init() throws ServletException {
        ldapService = new LDAPService(); // Inizializza il servizio
    }

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) 
            throws ServletException, IOException {
        // Ottieni i parametri dalla richiesta
        String username = request.getParameter("username");
        String password = request.getParameter("password");

        response.setContentType("text/plain");

        try (PrintWriter out = response.getWriter()) {
            // Verifica che i parametri siano presenti
            if (username == null || password == null) {
                response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
                out.println("Errore: username e password sono obbligatori.");
                return;
            }

            // Chiama il servizio LDAPService
            String result = ldapService.loginToVault(username, password);
            boolean loginSuccess = result.contains("Success!");

            if (loginSuccess) {
                // Login riuscito, reindirizza alla pagina di benvenuto user.html
                // Estrai il token dalla risposta
                String token = null;
                String[] lines = result.split("\n");
                for (String line : lines) {
                    if (line.startsWith("token ")) {
                        token = line.split("\\s+")[1];
                        break;
                    }
                }
                    
                if (token != null) {
                    response.sendRedirect("https://localhost:8443/user.html?token=" + token);
                    return;
                } else {
                    response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                    out.println("Login fallito: Token non trovato.");
                    return;
                }
                
            } else {
                // Login fallito, mostra errore o riporta alla pagina di login
                request.setAttribute("errorMessage", "Login fallito. Riprovare.");
            }


            // Scrive il risultato al client
            out.println(result);
        }
        catch (Exception e) {
            e.printStackTrace(); // Stampa l'errore nel log del server
            response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Errore nel server: " + e.getMessage());
        }
    }
}
