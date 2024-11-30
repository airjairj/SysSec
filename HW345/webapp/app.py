from flask import Flask, flash, render_template, request, redirect, session, jsonify
import requests
import secrets
import os

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

VAULT_ADDR = "http://vault:8200"  # Usa HTTP se Vault è configurato senza HTTPS
VAULT_VERIFY = False  # Imposta su True se Vault è configurato con un certificato SSL valido

@app.route("/")
def index():
    if "vault_token" in session:
        return redirect("/dashboard")
    return render_template("login.html")

@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username")
    password = request.form.get("password")

    url = f"{VAULT_ADDR}/v1/auth/ldap/login/{username}"
    payload = {"password": password, "username": username}
    
    try:
        # Richiesta per autenticare l'utente tramite LDAP su Vault
        response = requests.post(url, json=payload, verify=VAULT_VERIFY, headers={"Content-Type": "application/json"})

        response.raise_for_status()  # Se la risposta non è OK, solleva un'eccezione

        # Recupera il token di autenticazione da Vault
        data = response.json()
        session["vault_token"] = data["auth"]["client_token"]
        session["username"] = username

        # Ottieni informazioni sul token, incluse le policy assegnate
        token_url = f"{VAULT_ADDR}/v1/auth/token/lookup-self"
        headers = {"X-Vault-Token": session["vault_token"]}
        token_response = requests.get(token_url, headers=headers, verify=VAULT_VERIFY)
        token_response.raise_for_status()

        # Recupera le policy dal token
        policies = token_response.json().get("data", {}).get("policies", [])
        
        # Se l'utente ha la policy "amministratori", assegna il ruolo "admin"
        if "amministratori" in policies:
            role = "amministratore"
        elif "utenti" in policies:
            role = "utente"
        else:
            role = "ERRORE"
        
        # Salva il ruolo dell'utente nella sessione
        session["role"] = role

        return redirect("/dashboard")
    
    except requests.exceptions.RequestException as e:
        flash(f"Errore durante il login: {str(e)}", "error")
        return redirect("/")


@app.route("/dashboard", methods=["GET", "POST"])
def dashboard():
    if "vault_token" not in session:
        return redirect("/")

    username = session["username"]
    role = session.get("role")
    secrets_list = []

    # URL per elencare tutti i segreti
    list_url = f"{VAULT_ADDR}/v1/secret/metadata/"
    headers = {"X-Vault-Token": session["vault_token"], "accept": "application/json"}

    try:
        # Effettua la richiesta LIST per ottenere tutte le chiavi a livello principale
        list_response = requests.request("LIST", list_url, headers=headers, verify=VAULT_VERIFY)
        list_response.raise_for_status()

        # Recupera la lista delle chiavi dai metadati
        keys = list_response.json().get("data", {}).get("keys", [])
        
        # Itera sulle chiavi per ottenere i valori dei segreti
        for key in keys:
            secret_url = f"{VAULT_ADDR}/v1/secret/data/{key.strip('/')}"
            try:
                secret_response = requests.get(secret_url, headers=headers, verify=VAULT_VERIFY)
                secret_response.raise_for_status()
                secret_data = secret_response.json().get("data", {}).get("data", {})
                
                # Aggiungi il segreto alla lista in formato "key: value"
                secrets_list.append({key: secret_data})
            except requests.exceptions.RequestException as e:
                flash(f"Errore nel recupero del segreto {key}: {str(e)}", "error")

    except requests.exceptions.RequestException as e:
        flash(f"Errore nel recupero della lista dei segreti: {str(e)}", "error")

    return render_template("dashboard.html", username=username, role=role, secrets=secrets_list)


@app.route("/add_secret", methods=["POST"])
def add_secret():
    if session.get("role") != "amministratore":
        flash("Non hai i permessi per aggiungere segreti.", "error")
        return redirect("/dashboard")

    secret_name = request.form.get("secret_name")
    secret_value = request.form.get("secret_value")
    username = session["username"] 

    # URL per Vault
    secret_url = f"{VAULT_ADDR}/v1/secret/data/{username}"
    
    # Header con il token Vault
    headers = {
        "X-Vault-Token": session["vault_token"],
        "Content-Type": "application/json",
        "accept": "application/json"
    }
    
    # Payload per la richiesta
    payload = {
        "data": {
            secret_name : secret_value
        },
        "options": {},
        "version": 1
    }

    try:
        # Effettua la richiesta POST
        response = requests.post(secret_url, headers=headers, json=payload, verify=VAULT_VERIFY)
        response.raise_for_status()
        flash("Segreto aggiunto con successo.", "success")
    except requests.exceptions.RequestException as e:
        flash(f"Errore nell'aggiunta del segreto: {str(e)}", "error")

    return redirect("/dashboard")

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")

if __name__ == "__main__":
    # Configura il contesto SSL se necessario (modifica con i tuoi percorsi)
    context=('/certs/server.crt', '/certs/server.key')
    app.run(debug=True, host="0.0.0.0", port=5000, ssl_context=context)