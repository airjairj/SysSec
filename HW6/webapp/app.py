import base64
from flask import Flask, flash, json, render_template, request, redirect, session, jsonify
import requests
import secrets
import logging

logging.basicConfig(level=logging.DEBUG)


app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

# URL di Keycloak
keycloak_url = "http://keycloak:8080/realms/myrealm/protocol/openid-connect/token"
client_id = "webapp"
client_secret = "oLHKrESSsjv0yK05HpQRavEorUXqJ9hz" 

@app.route("/")
def index():
    return render_template("login.html")

@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username")
    password = request.form.get("password")
    
    payload = {
        "client_id": client_id,
        "client_secret": client_secret,
        "grant_type": "password",
        "username": username,
        "password": password,
    }

    try:
        # Richiedi un token a Keycloak
        response = requests.post(keycloak_url, data=payload)
        if response.status_code == 400:
            flash("Credenziali non valide", "Errore")
            return redirect("/") 
        elif response.status_code != 200:
            print(f"Errore da Keycloak: {response.status_code}, {response.text}")
        response.raise_for_status()

        # Estrarre il token JWT dalla risposta
        token_data = response.json()
        jwt_token = token_data["access_token"]

        # Logga il token prima di decodificarlo
        logging.debug(f"JWT token ricevuto: {jwt_token}")

        # Decodifica il token JWT
        token_parts = jwt_token.split('.')
        token_payload = token_parts[1]
        token_payload += '=' * (4 - len(token_payload) % 4)  # Aggiungi padding se necessario
        decoded_payload = json.loads(base64.urlsafe_b64decode(token_payload).decode('utf-8'))

        # Logga il payload decodificato
        logging.debug("Decoded JWT payload: %s", decoded_payload)
        
        # Stampa il payload decodificato per il debug
        print("Decoded JWT payload:", decoded_payload)

        # Salva il token JWT e il ruolo nella sessione
        session["jwt_token"] = jwt_token
        session["username"] = username
        session["role"] = decoded_payload.get("realm_access", {}).get("roles", [])[0] if decoded_payload.get("realm_access", {}).get("roles") else "ERRORE"

        # Redirect alla dashboard dopo il login
        return redirect("/dashboard")

    except requests.exceptions.RequestException as e:
        flash(f"Errore durante il login: {str(e)}", "error")
        return redirect("/")

@app.route("/dashboard", methods=["GET", "POST"])
def dashboard():
    if "jwt_token" not in session:
        return redirect("/")

    username = session["username"]
    role = session["role"]
    return render_template("dashboard2.html", username=username, role=role)

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")

if __name__ == "__main__":
    # Configura il contesto SSL se necessario (modifica con i tuoi percorsi)
    context=('/certs/server.crt', '/certs/server.key')
    app.run(debug=True, host="0.0.0.0", port=5000, ssl_context=context)