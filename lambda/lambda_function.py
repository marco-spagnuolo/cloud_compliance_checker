import boto3

def lambda_handler(event, context):
    instance_id = event['detail']['instance-id']
    ec2 = boto3.client('ec2')
    
    # Isolate instance by changing its security group
    response = ec2.modify_instance_attribute(
        InstanceId=instance_id,
        Groups=['sg-0ee645f2ff11d765b'] # Security group that blocks all traffic
    )
    
    return f"Instance {instance_id} isolated successfully"
