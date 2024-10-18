import boto3
import os
import subprocess
import sys
from botocore.exceptions import ClientError

s3 = boto3.client('s3')

def lambda_handler(event, context):
    # Get the object from the event
    bucket = event['Records'][0]['s3']['bucket']['name']
    key = event['Records'][0]['s3']['object']['key']

    try:
        # Download the object from S3 to Lambda's /tmp directory
        download_path = f'/tmp/{key}'
        s3.download_file(bucket, key, download_path)

        # Run ClamAV scan
        result = subprocess.run(['clamscan', download_path], stdout=subprocess.PIPE)
        scan_result = result.stdout.decode('utf-8')

        if 'FOUND' in scan_result:
            print(f'Malware detected in {key} from {bucket}: {scan_result}')
            # Take actions like quarantining or deleting the file
        else:
            print(f'No malware found in {key} from {bucket}. Scan result: {scan_result}')

    except ClientError as e:
        print(f'Error getting object {key} from bucket {bucket}. Make sure it exists. Error: {e}')
        raise e
