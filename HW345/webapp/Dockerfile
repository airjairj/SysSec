FROM python:3.9-slim

# Installazione dei pacchetti necessari
RUN apt-get update && apt-get install -y \
    openssl \
    && rm -rf /var/lib/apt/lists/*

# Crea una cartella per i certificati
RUN mkdir /certs

# Genera il certificato SSL auto-firmato
RUN openssl req -x509 -newkey rsa:2048 -keyout /certs/server.key -out /certs/server.crt -days 365 -nodes \
    -subj "/C=US/ST=State/L=City/O=Org/CN=localhost"

# Installa le dipendenze della webapp
WORKDIR /app
COPY requirements.txt /app/
RUN pip install -r requirements.txt
COPY . /app/

# Expose the port
EXPOSE 5173

CMD ["python", "app.py"]
