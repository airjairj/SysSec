import json

class Policy:
    def __init__(self, policy_id, rules, combining_algorithm="first-applicable"):
        self.policy_id = policy_id
        self.rules = rules
        self.combining_algorithm = combining_algorithm

    @staticmethod
    def load_from_file(file_path):
        """
        Carica una policy da un file JSON.
        """
        with open(file_path, 'r') as f:
            data = json.load(f)
        return Policy(
            policy_id=data["policy_id"],
            rules=data["rules"],
            combining_algorithm=data.get("rule_combining_algorithm", "first-applicable")
        )

class PDP:
    @staticmethod
    def evaluate(policy, request):
        """
        Valuta la richiesta rispetto alla policy, applicando l'algoritmo di combinazione delle regole.
        """
        for rule in policy.rules:
            if PDP._evaluate_rule(rule, request):
                return rule["effect"]
        
        return "NotApplicable"

    @staticmethod
    def _evaluate_rule(rule, request):
        """
        Valuta una singola regola rispetto alla richiesta.
        """
        # Condizione principale (ad esempio, basata sul ruolo)
        if not PDP._evaluate_condition(rule["role_condition"], request):
            return False
        
        # Condizione della risorsa (se presente)
        if "resource_condition" in rule:
            if not PDP._evaluate_condition(rule["resource_condition"], request):
                return False
            
        # Condizione dell'azione (se presente)
        if "action_condition" in rule:
            if not PDP._evaluate_condition(rule["action_condition"], request):
                return False

        return True

    @staticmethod
    def _evaluate_condition(condition, request):
        """
        Valuta una generica condizione (ad esempio, attributo, operatore e valore).
        """
        attribute = condition["attribute"]
        operator = condition["operator"]
        value = condition["value"]

        # Verifica se l'attributo è presente nella richiesta, se non lo è restituisce False per motivi di sicurezza
        # Questo comportamento può essere modificato, ma non è consigliabile
        if attribute not in request:
            return False

        if operator == "equals":
            print(f"request = {request}\nrequest[attribute] = {request[attribute]}, value = {value}\n")
            if attribute == "action":
                # Per l'azione, facciamo un'eccezione alla generalizzazione per consentire più tipi di azioni in una singola regola
                # Le singole azioni sono ancora possibili e preferibili, ma questo può essere conveniente
                return request[attribute] in value
            return request[attribute] == value
        return False

class PIP:
    @staticmethod
    def resolve_attributes(request):
        """
        Arricchisce la richiesta con valori predefiniti per gli attributi mancanti.
        I ruoli, le risorse e le azioni predefinite possono essere usati nella policy per consentire o negare l'accesso in casi di
        richiesta/e non valide, aggiungendo un livello di sicurezza.
        """
        if "role" not in request:
            request["role"] = "guest"           # Ruolo predefinito
        
        if "resource" not in request:
            request["resource"] = "not found"   # Risorsa predefinita
        
        if "action" not in request:
            request["action"] = "unknown"       # Azione predefinita
        
        return request


# Funzione principale
def main():
    # Carica la policy, simulando il PAP
    policy = Policy.load_from_file("C:\\Users\\hp\\Documents\\Esami In Corso\\System Sec\\Homework\\SysSec\\HW5\\policy.json")
    print(f"Policy = {policy.policy_id}")
    print(f"Algoritmo di Combinazione = {policy.combining_algorithm}\n\n")

    # Richieste di test
    # Richiesta iniziale [DENY]
    # request = {'action': 'w', 'resource': 'confidential', 'role': 'guest'}
    
    # Richiesta senza ruolo [DENY]
    # request = {'action': 'r', 'resource': 'confidential'}

    # Richiesta con ruolo admin [PERMIT]
    # request = {"action": "r", "resource": "confidential", "role": "admin"}

    request = {"action": "r", "resource": "confidential", "role": "admin"}

    # Arricchisce gli attributi usando PIP
    request = PIP.resolve_attributes(request)

    # Valuta la richiesta usando PDP
    decision = PDP.evaluate(policy, request)

    # Output
    print("Request:", request)
    print("Decision:", decision)

if __name__ == "__main__":
    main()
