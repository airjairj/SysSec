from flask import Flask, flash, render_template, request, redirect, session,  url_for
import requests
import jwt
from urllib.parse import urlencode
import secrets
import vakt
from vakt.rules import Eq, StartsWith, And, Greater, Less, Any # Importa tutto il set di regole di VAKT
import urllib3
from datetime import timedelta, datetime
from flask_sqlalchemy import SQLAlchemy
from authlib.integrations.flask_client import OAuth

import logging
urllib3.disable_warnings() # Serve perchè senza non funziona bene la webapp dato che i certificati sono auto firmati

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)
app.permanent_session_lifetime = timedelta(minutes=10)  # AC-12: Inattività massima, impostata ad 10 minuti per testare
oauth = OAuth(app)
VAULT_ADDR = "https://localhost:8200"  # Usa HTTP se Vault è configurato senza HTTPS
VAULT_VERIFY = False  # Imposta su True se Vault è configurato con un certificato SSL valido
redirect_uri = "https://localhost:5173"
keycloak_url = "http://localhost:8080"
realm_name = "SystemSecurity"
client_id = "FranAva"
client_secret = "Y00EvlImnhpuC5XOpHLxC2sly5BmQT4u"
token_url = "https://oauth2.googleapis.com/token"


# VAKT
# Definisci le policy in VAKT
policies = [
    vakt.Policy(
        1,
        actions=[Eq('Add')],
        resources=[StartsWith('Ordine')],
        subjects=[{'Role': Eq('amministratore')}],
        effect=vakt.ALLOW_ACCESS,
        description="""Consenti l'aggiunta di ordini agli amministratori"""
    ),
    vakt.Policy(
        2,
        actions=[Eq('Add')],
        resources=[StartsWith('Ordine')],
        subjects=[{'Role': Eq('utente')}],
        effect=vakt.ALLOW_ACCESS,
        description="""Consenti l'aggiunta di ordini agli utenti"""
    ),
    vakt.Policy(
        3,
        actions=[Eq('Delete')],
        resources=[StartsWith('Ordine')],
        subjects=[{'Role': Eq('amministratore')}],
        effect=vakt.ALLOW_ACCESS,
        description="""Consenti l'eliminazione di ordini agli amministratori"""
    ),
    vakt.Policy(
        4,
        actions=[Eq('Delete')],
        resources=[StartsWith('Ordine')],
        subjects=[{'Role': Eq('utente')}],
        effect=vakt.DENY_ACCESS,
        description="""Non consentire l'eliminazione di ordini agli utenti"""
    ),
    vakt.Policy(
        5,
        actions=[Eq('Edit')],
        resources=[StartsWith('Ordine')],
        subjects=[{'Role': Eq('amministratore')}],
        effect=vakt.ALLOW_ACCESS,
        description="""Consenti la modifica di ordini agli amministratori"""
    ),
    vakt.Policy(
        6,
        actions=[Eq('Edit')],
        resources=[StartsWith('Ordine')],
        subjects=[{'Role': Eq('utente')}],
        effect=vakt.DENY_ACCESS,
        description="""Non consentire la modifica di ordini agli utenti"""
    )
]

# Memorizza le policy in VAKT
storage = vakt.MemoryStorage()
for policy in policies:
    storage.add(policy)
guard = vakt.Guard(storage, vakt.RulesChecker())


# DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////Users/francescoavallone/Desktop/SysSec/HW345/webapp/data/notes.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['TEMPLATES_AUTO_RELOAD'] = True
db = SQLAlchemy(app)

# Struttura della tabella delle note
class Tabella(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.String(500), nullable=False)
    username = db.Column(db.String(100), nullable=False)

    def __repr__(self):
        return f"<Tabella {self.id} - {self.username}>"

# Creazione delle tabelle
with app.app_context():
    db.create_all()




@app.before_request
def check_inactivity():
    session.permanent = True
    last_activity = session.get('last_activity')
    now = datetime.now()

    if last_activity:
        elapsed_time = now - datetime.strptime(last_activity, "%Y-%m-%d %H:%M:%S")
        if elapsed_time > app.permanent_session_lifetime:
            session.clear()
            return redirect(url_for('logout'))

    # Aggiorna il timestamp per l'attività corrente
    session['last_activity'] = now.strftime("%Y-%m-%d %H:%M:%S")

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
        flash(f"Credenziali errate", "error")
        print(url)
        print(username + password)
        return redirect("/")
    
@app.route('/loginOPENID')
def loginOPENID():

    authorize_url = f"{keycloak_url}/realms/{realm_name}/protocol/openid-connect/auth"
    redirect_uri_callback = f"{redirect_uri}/callback"
    params = { 'client_id': client_id, 'redirect_uri': redirect_uri_callback, 'response_type': 'code', 'scope': 'openid profile email' }


    if 'username' not in session: 
        return redirect(f"{authorize_url}?{'&'.join([f'{key}={value}' for key, value in params.items()])}")


    userinfo_endpoint = f"{keycloak_url}/realms/{realm_name}/protocol/openid-connect/userinfo"
    headers = {'Authorization': f"Bearer {session['access_token']}"}
    response = requests.get(userinfo_endpoint, headers=headers)

    if response.status_code == 200:
        return redirect("/dashboard")
    else:
        logging.info("Access token scaduto, tentativo di refresh...")
        refresh_token = session['user']['refresh_token']
        token_endpoint = f"{keycloak_url}/realms/{realm_name}/protocol/openid-connect/token"
        payload = { 'client_id': client_id, 'grant_type': 'refresh_token', 'refresh_token': refresh_token, 'client_secret': client_secret}
        token_response = requests.post(token_endpoint, data=payload)
        if token_response.status_code == 200: # ma il refresh token è ancora valido
            new_tokens = token_response.json()
            session['access_token'] = new_tokens['access_token']
            session['refresh_token'] = new_tokens['refresh_token']
            session['id_token'] = new_tokens['id_token']
            logging.info("Token aggiornati con successo.")

@app.route("/callback")
def callback():
    code = request.args.get('code')
    logging.debug(f"Callback received with code: {code}")
    redirect_uri_callback = f"{redirect_uri}/callback"

    token_endpoint = f"{keycloak_url}/realms/{realm_name}/protocol/openid-connect/token"

    payload = { 
        'grant_type': 'authorization_code',
        'code': code,
        'redirect_uri': redirect_uri_callback,
        'client_id': client_id,
        'client_secret': client_secret
    }

    try:
        response = requests.post(token_endpoint, data=payload)
        logging.debug(f"payload: {response}")
        token_data = response.json()
        print(token_data)

        if 'access_token' in token_data:
            userinfo_endpoint = f"{keycloak_url}/realms/{realm_name}/protocol/openid-connect/userinfo"
            headers = {'Authorization': f"Bearer {token_data['access_token']}"}
            userinfo_response = requests.get(userinfo_endpoint, headers=headers)
            userinfo = userinfo_response.json()
            
            session['access_token'] = token_data.get('access_token')
            session['refresh_token'] = token_data.get('refresh_token')
            session['username'] = userinfo.get('preferred_username')
            session['email'] = userinfo.get('email')
            session['role'] = "amministratore"
            session["id_token"] = token_data.get('id_token')

            decoded_token = jwt.decode(session['access_token'], options={"verify_signature": False})
            roles = decoded_token.get('realm_access', {}).get('roles', [])
            if "Amministratore" in roles: 
                session["role"] = "amministratore"
            elif "Utente" in roles: 
                session["role"] = "utente"
            else: 
                return "Denied Access."


            logging.debug("User logged in successfully.")
            return redirect("/dashboard")
        else:
            logging.error("Failed to fetch tokens.")
            return "Failed to fetch tokens."

    except Exception as e:
        logging.error(f"Exception during token exchange: {e}")
        return "Failed to fetch tokens."


@app.route("/dashboard", methods=["GET", "POST"])
@app.route("/tabella", methods=["GET", "POST"])
def notes():
    referrer = request.referrer
    if referrer and "login" in referrer:
        if "vault_token" not in session:
            return redirect("/")

    username = session["username"]
    role = session.get("role", "utente")

    if role == "amministratore":
        all_notes = Tabella.query.all()
    else:
        all_notes = Tabella.query.filter_by(username=username).all()

    return render_template("tabella.html", notes=all_notes)

@app.route("/add-note", methods=["GET", "POST"])
def add_note():
    referrer = request.referrer
    if referrer and "login" in referrer:
        if "vault_token" not in session:
            return redirect("/")

        if request.method == "POST":
            inquiry = vakt.Inquiry(
                action="Add",
                resource="Ordine",
                subject={"Role": session["role"]},
            )

            if guard.is_allowed(inquiry):
                content = request.form.get("content")
                username = session["username"]
                if content:
                    new_note = Tabella(content=content, username=username)
                    db.session.add(new_note)
                    db.session.commit()
                    
                    flash("Pensiero aggiunto con successo!", "success")
                    return redirect("/tabella")
            else:
                flash("Non hai i permessi per aggiungere un pensiero in questo momento.", "error")
                return redirect("/tabella")
    
    else: 
        if request.method == "POST":
            content = request.form.get("content")
            username = session["username"]
            if content:
                new_note = Tabella(content=content, username=username)
                db.session.add(new_note)
                db.session.commit()
                    
                flash("Pensiero aggiunto con successo!", "success")
                return redirect("/tabella")


    return render_template("add_note.html")

@app.route("/edit-note/<int:id>", methods=["GET", "POST"])
def edit_note(id):
    referrer = request.referrer
    if referrer and "login" in referrer:
        if "vault_token" not in session:
            return redirect("/")

        note = Tabella.query.get_or_404(id)

        if request.method == "POST":
            inquiry = vakt.Inquiry(
                action="Edit",
                resource="Ordine",
                subject={"Role": session["role"]},
            )

            if guard.is_allowed(inquiry):
                new_content = request.form.get("content")
                if new_content:
                    note.content = new_content
                    db.session.commit()
                    
                    
                    flash("Nota modificata con successo!", "success")
                    return redirect("/tabella")
            else:
                flash("Non hai i permessi per modificare questa nota in questo momento.", "error")
                return redirect("/tabella")
            
    else: 
        note = Tabella.query.get_or_404(id)
        if request.method == "POST":
            new_content = request.form.get("content")
            if new_content and session["role"] == "amministratore":
                note.content = new_content
                db.session.commit()
                flash("Pensiero modificato con successo!", "success")
                return redirect("/tabella")
            
            else:
                flash("Non hai i permessi per modificare questo pensiero al momento.", "error")
                return redirect("/tabella")

    return render_template("edit_note.html", note=note)

@app.route("/delete-note/<int:id>", methods=["POST"])
def delete_note(id):
    referrer = request.referrer
    if referrer and "login" in referrer:
        if "vault_token" not in session:
            return redirect("/")

        note = Tabella.query.get_or_404(id)

        inquiry = vakt.Inquiry(
            action='Delete',
            resource='Ordine',
            subject={'Role': session['role']},
        )

        if guard.is_allowed(inquiry):
            db.session.delete(note)
            db.session.commit()

            flash("Pensiero eliminato con successo!", "success")
            return redirect("/tabella")
        else:
            flash("Non hai i permessi per eliminare questo pensiero al questo momento.", "error")
            return redirect("/tabella")
        
    else: 
        note = Tabella.query.get_or_404(id)

        if session["role"] == "amministratore":
            db.session.delete(note)
            db.session.commit()

            flash("Pensiero eliminato con successo!", "success")
            return redirect("/tabella")
        
        else:
            flash("Non hai i permessi per eliminare questo pensiero al momento.", "error")
            return redirect("/tabella")

@app.route("/logout")
def logout():
    end_session_endpoint = f"{keycloak_url}/realms/{realm_name}/protocol/openid-connect/logout"

    id_token = session['id_token']        
    post_logout_redirect_uri = 'https://localhost:5173/'
    params = { 'client_id': client_id, 'id_token_hint': id_token, 'post_logout_redirect_uri': post_logout_redirect_uri}
    session.clear()
    response = requests.get(end_session_endpoint + '?' + urlencode(params))
    return redirect(url_for('index'))

if __name__ == "__main__":
    # Configura il contesto SSL se necessario (modifica con i tuoi percorsi)
    context=('/Users/francescoavallone/Desktop/SysSec/HW345/certs/server.crt', '/Users/francescoavallone/Desktop/SysSec/HW345/certs/server.key')
    app.run(debug=True, host="localhost", port=5173, ssl_context=context)


