from flask import Flask, flash, render_template, request, redirect, session,  url_for
import requests
import secrets
import vakt
from vakt.rules import Eq, StartsWith, And, Greater, Less, Any # Importa tutto il set di regole di VAKT
import urllib3
from datetime import timedelta, datetime
from flask_sqlalchemy import SQLAlchemy
from authlib.integrations.flask_client import OAuth
from authlib.jose import jwt

urllib3.disable_warnings() # Serve perchè senza non funziona bene la webapp dato che i certificati sono auto firmati

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)
app.permanent_session_lifetime = timedelta(minutes=10)  # AC-12: Inattività massima, impostata ad 10 minuti per testare
oauth = OAuth(app)
VAULT_ADDR = "https://localhost:8200"  # Usa HTTP se Vault è configurato senza HTTPS
VAULT_VERIFY = False  # Imposta su True se Vault è configurato con un certificato SSL valido

oauth.register(
    name="google",
    client_id="292219212098-q10f6k4mgjkp8lj7v0drpu0hqdpsrqfr.apps.googleusercontent.com",
    client_secret="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",
    server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
    redirect_uri='https://localhost:5173/callback',
    client_kwargs={"scope": "openid email profile"},
)

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
app = Flask(__name__)


# DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////Users/francescoavallone/Desktop/UNIVERSITA/SystemSecurity/SysSec/HW345/webapp/data/notes.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
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
    nonce = secrets.token_urlsafe(16)
    session["oauth_state"] = {"nonce": nonce}
    return oauth.google.authorize_redirect(url_for("callback", _external=True), nonce=nonce)

@app.route("/callback")
def callback():
    token = oauth.google.authorize_access_token()
    nonce = session.get("oauth_state", {}).get("nonce")
    user_info = oauth.google.parse_id_token(token, nonce=nonce)

    session['user'] = user_info
    session["username"] = user_info["name"] + " (" + user_info["email"] +")"
    session["role"] = "utente"

    url = f"{VAULT_ADDR}/v1/auth/jwt/login"
    headers = {"Content-Type": "application/json"}
    payload = {"role": "utente", "jwt": token["id_token"]}

    response = requests.post(url, json=payload, headers=headers, verify=False)

    data = response.json()

    session["vault_token"] = data["auth"]["client_token"]
    
    return redirect("/dashboard")

@app.route("/dashboard", methods=["GET", "POST"])
@app.route("/tabella", methods=["GET", "POST"])
def notes():
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
                
                flash("Nota aggiunta con successo!", "success")
                return redirect("/tabella")
        else:
            flash("Non hai i permessi per aggiungere una nota in questo momento.", "error")
            return redirect("/tabella")


    return render_template("add_note.html")

@app.route("/edit-note/<int:id>", methods=["GET", "POST"])
def edit_note(id):
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

    return render_template("edit_note.html", note=note)

@app.route("/delete-note/<int:id>", methods=["POST"])
def delete_note(id):
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

        flash("Nota eliminata con successo!", "success")
        return redirect("/tabella")
    else:
        flash("Non hai i permessi per eliminare questa nota in questo momento.", "error")
        return redirect("/tabella")

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")

if __name__ == "__main__":
    # Configura il contesto SSL se necessario (modifica con i tuoi percorsi)
    context=('/Users/francescoavallone/Desktop/UNIVERSITA/SystemSecurity/SysSec/HW345/cert1.crt', '/Users/francescoavallone/Desktop/UNIVERSITA/SystemSecurity/SysSec/HW345/key1.key')
    app.run(debug=True, host="localhost", port=5173, ssl_context=context)