import boto3
import json

# Inizializzazione del client EventBridge
eventbridge_client = boto3.client('events')

def create_cloudwatch_rule(lambda_arn):
    """
    Crea una regola di CloudWatch per catturare findings di GuardDuty con severità >= 7
    e attivare una funzione Lambda per la risposta automatica.
    """
    try:
        # Definisce il pattern dell'evento per catturare findings di GuardDuty con severità >= 7
        event_pattern = {
            "source": ["aws.guardduty"],
            "detail-type": ["GuardDuty Finding"],
            "detail": {
                "severity": [{"numeric": ["greaterThanOrEqual", 7]}]
            }
        }

        # Crea la regola su EventBridge (CloudWatch Events)
        rule_response = eventbridge_client.put_rule(
            Name='GuardDutyHighSeverityResponse',
            EventPattern=json.dumps(event_pattern),
            State='ENABLED',
            Description='Trigger per attivare la Lambda su findings di GuardDuty con severità >= 7',
        )

        # Aggiungi la Lambda come target della regola
        target_response = eventbridge_client.put_targets(
            Rule='GuardDutyHighSeverityResponse',
            Targets=[
                {
                    'Id': '1',
                    'Arn': lambda_arn  # ARN della funzione Lambda
                }
            ]
        )

        print(f"Regola CloudWatch creata con successo: {rule_response['RuleArn']}")
        print(f"Target aggiunto alla regola: {target_response}")

    except Exception as e:
        print(f"Errore durante la creazione della regola di CloudWatch: {str(e)}")

# ARN della tua funzione Lambda (sostituisci con il tuo ARN)
lambda_arn = "arn:aws:lambda:region:account-id:function:my-incident-response-lambda"

# Crea la regola di CloudWatch
create_cloudwatch_rule(lambda_arn)
