package com.gruppo.servlet;

import java.util.HashMap;
import java.util.Map;

import com.bettercloud.vault.Vault;
import com.bettercloud.vault.VaultConfig;
import com.bettercloud.vault.VaultException;
import com.bettercloud.vault.response.LogicalResponse;

public class VaultService {
    private final Vault vault;

    public VaultService() throws VaultException {
        // Configura Vault per connettersi al server
        VaultConfig config = new VaultConfig()
            .address("http://127.0.0.1:8200") // URL di Vault
            .token("hvs.C2qBHXogxXbQexHFBgR1PAd9") // Token di autenticazione
            .build();

        vault = new Vault(config);
    }

    // Metodo per ottenere un secret da Vault
    public String getSecret(String secretPath, String key) {
        try {
            // Leggi il secret dal path fornito
            LogicalResponse response = vault.logical().read(secretPath);
    
            // Verifica che i dati non siano nulli
            if (response != null && response.getData() != null) {
                // Assicurati che TESTKEY esista nella mappa
                Object secretValue = response.getData().get(key);
                if (secretValue != null) {
                    return secretValue.toString(); // Restituisci il valore del secret come stringa
                } else {
                    System.err.println("Secret key " + key + "not found in the response.");
                    return "Secret key " + key + " not found in the response.";
                }
            } else {
                System.err.println("No data found for secret path: " + secretPath);
                return "No data found for secret path: " + secretPath;
            }
        } catch (VaultException e) {
            // Gestione delle eccezioni di Vault
            System.err.println("VaultException occurred: " + e.getMessage());
            return null;
        } catch (Exception e) {
            // Gestione di eventuali altre eccezioni
            System.err.println("An unexpected error occurred: " + e.getMessage());
            return null;
        }
    }

    // Metodo per aggiungere un segreto in Vault
    public boolean addSecret(String secretPath, String key, String value) {
        try {
            // Crea un oggetto Map per il segreto
            Map<String, Object> secretData = new HashMap<>();
            secretData.put(key, value);

            // Scrivi il segreto in Vault
            LogicalResponse response = vault.logical().write(secretPath, secretData);

            // Verifica la risposta per confermare che il segreto è stato scritto correttamente
            if (response != null && response.getRestResponse().getStatus() == 200) {
                System.out.println("Secret added successfully to path: " + secretPath);
                return true;
            } else {
                System.err.println("Failed to add secret.");
                if (response != null && response.getRestResponse() != null) {
                    System.err.println("Response status: " + response.getRestResponse().getStatus());
                } else {
                    System.err.println("Response or RestResponse is null.");
                }
                return false;
            }
        } catch (VaultException e) {
            System.err.println("VaultException occurred: " + e.getMessage());
            return false;
        } catch (Exception e) {
            System.err.println("An unexpected error occurred: " + e.getMessage());
            return false;
        }
    }
}