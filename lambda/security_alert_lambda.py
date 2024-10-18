import boto3
import requests
import json
import os
from datetime import datetime

# SNS client
sns = boto3.client('sns')
ssm = boto3.client('ssm')

# External security alert sources (example: CISA)
CISA_ALERTS_API = "https://www.cisa.gov/uscert/ncas/alerts.json"
SNS_TOPIC_ARN = os.environ['SNS_TOPIC_ARN']  # SNS topic for internal alerts

def lambda_handler(event, context):
    # Step 1: Fetch external security alerts from CISA (or other sources)
    response = requests.get(CISA_ALERTS_API)
    alerts = response.json()

    # Step 2: Filter relevant alerts and disseminate internally via SNS
    for alert in alerts['alerts']:
        title = alert['title']
        link = alert['link']
        date_posted = alert['date_posted']
        
        # Generate an internal alert for important advisories
        if is_relevant_alert(alert):
            send_internal_alert(title, link, date_posted)

        # Step 3: Track advisories via AWS SSM for compliance
        track_security_advisory(alert)

    return {
        'statusCode': 200,
        'body': json.dumps('Security alerts processed')
    }

# Function to determine if an alert is relevant
def is_relevant_alert(alert):
    # You can customize this logic to filter important alerts (e.g., based on severity)
    return 'critical' in alert['title'].lower()

# Function to send internal alerts via SNS
def send_internal_alert(title, link, date_posted):
    message = f"Security Advisory: {title}\nPosted on: {date_posted}\nRead more: {link}"
    response = sns.publish(
        TopicArn=SNS_TOPIC_ARN,
        Message=message,
        Subject=f"Security Alert: {title}"
    )
    print(f"Alert sent via SNS: {response['MessageId']}")

# Function to track the advisory in SSM for compliance
def track_security_advisory(alert):
    alert_id = alert['id']
    title = alert['title']
    link = alert['link']
    date_posted = alert['date_posted']

    # Store advisory details in SSM Parameter Store for compliance tracking
    param_name = f"/security/advisories/{alert_id}"
    ssm.put_parameter(
        Name=param_name,
        Value=json.dumps({
            'title': title,
            'link': link,
            'date_posted': date_posted,
            'status': 'pending'
        }),
        Type='String',
        Overwrite=True
    )
    print(f"Advisory tracked in SSM: {param_name}")
