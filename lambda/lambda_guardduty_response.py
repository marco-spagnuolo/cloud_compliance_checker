def lambda_handler(event, context):
    logger.info(f"Event received: {json.dumps(event)}")

    detail = event.get('detail', {})
    severity = detail.get('severity', 0)

    if severity >= 7:
        logger.info(f"Severity of the incident: {severity}. Executing response...")
        
        resource = detail.get('resource', {}).get('instanceDetails', {})
        instance_id = resource.get('instanceId')

        if instance_id:
            logger.info(f"Isolating EC2 instance: {instance_id}")
            isolate_ec2_instance(instance_id)
        else:
            logger.warning("No EC2 instance associated with the GuardDuty finding.")
    else:
        logger.info(f"Incident severity too low: {severity}. No action taken.")
