from flask_sqlalchemy import SQLAlchemy

# Inizializza l'oggetto db, che sarà usato nel resto dell'applicazione
db = SQLAlchemy()

# Struttura della tabella
class Tabella(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.String(500), nullable=False)
    username = db.Column(db.String(100), nullable=False)

    def __repr__(self):
        return f"<Tabella {self.id} - {self.username}>"
