package com.gruppo.servlet;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

public class LDAPService {

    public String loginToVault(String username, String password) {
        // Usa il percorso corretto con "auth/ldap/login/"
        String apiUrl = "https://127.0.0.1:8200/v1/auth/ldap/login/" + username;
        String requestBody = String.format("{\"password\": \"%s\"}", password);

        HttpClient client = HttpClient.newHttpClient();
        HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create(apiUrl))
            .header("Content-Type", "application/json")
            .POST(HttpRequest.BodyPublishers.ofString(requestBody))
            .build();

        try {
            HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());

            // Controlla se la risposta è valida
            if (response.statusCode() == 200) {
                return response.body(); // Restituisce il corpo della risposta (token e altri dati)
            } else {
                throw new RuntimeException("Errore durante il login: codice di stato " + response.statusCode() +
                    " - Messaggio: " + response.body());
            }
        } catch (IOException | InterruptedException e) {
            return "Errore: " + e.getMessage();
        }
    }
}
