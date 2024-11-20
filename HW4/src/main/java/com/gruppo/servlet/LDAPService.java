package com.gruppo.servlet;

import java.io.BufferedReader;
import java.io.InputStreamReader;

public class LDAPService {

    public String loginToVault(String username, String password) {
        String command = String.format(
            "vault login -method=ldap username=\"%s\" password=\"%s\"",
            username, password
        );

        StringBuilder output = new StringBuilder();
        try {
            // Prepara il comando
            ProcessBuilder processBuilder = new ProcessBuilder();
            processBuilder.command("cmd", "/c", command); 

            // Avvia il processo
            Process process = processBuilder.start();

            // Legge l'output del comando
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\n");
            }

            // Attende la fine del processo
            int exitCode = process.waitFor();
            if (exitCode != 0) {
                throw new RuntimeException("Errore durante il login: codice di uscita " + exitCode);
            }
        } catch (Exception e) {
            return "Errore: " + e.getMessage();
        }

        return output.toString();
    }
}
