## 2. Install OSQuery on AWS EC2 Instances
SSH into your EC2 instance and install OSQuery:
For Amazon Linux 2:

```bash
sudo yum install -y osquery
```
For Ubuntu:

```bash
sudo apt-get update
sudo apt-get install -y osquery
```
## 3. Configure OSQuery

Create the OSQuery configuration file /etc/osquery/osquery.conf:

```json
{
  "options": {
    "config_plugin": "filesystem",
    "logger_plugin": "filesystem",
    "logger_path": "/var/log/osquery",
    "disable_logging": "false",
    "log_result_events": "true",
    "schedule_splay_percent": "10"
  },
  "schedule": {
    "users": {
      "query": "SELECT * FROM users WHERE uid >= 1000;",
      "interval": 3600
    },
    "ssh_access": {
      "query": "SELECT * FROM last WHERE tty = 'pts/0';",
      "interval": 3600
    },
    "session_monitor": {
      "query": "SELECT * FROM logged_in_users;",
      "interval": 600
    }
  }
}
```

## 4. Install and Configure the CloudWatch Agent
For Amazon Linux 2:

```bash
sudo yum install -y amazon-cloudwatch-agent
```

# For Ubuntu:

```bash
wget https://s3.amazonaws.com/amazoncloudwatch-agent/ubuntu/amd64/latest/amazon-cloudwatch-agent.deb
sudo dpkg -i amazon-cloudwatch-agent.deb
Create the CloudWatch Agent configuration file /opt/aws/amazon-cloudwatch-agent/bin/config.json:
```

```json
{
  "agent": {
    "metrics_collection_interval": 60,
    "logfile": "/var/log/amazon-cloudwatch-agent.log"
  },
  "logs": {
    "logs_collected": {
      "files": {
        "collect_list": [
          {
            "file_path": "/var/log/osquery/osqueryd.results.log",
            "log_group_name": "osquery-logs",
            "log_stream_name": "{instance_id}"
          }
        ]
      }
    }
  }
}
```

### Start the CloudWatch Agent:

```bash

sudo /opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl -a fetch-config -m ec2 -c file:/opt/aws/amazon-cloudwatch-agent/bin/config.json -s
```

## 5. Configure AWS IAM

    Go to the IAM console.
    Create a new IAM user or group with the necessary permissions.
    Attach policies to the user/group as required.

Enable MFA for IAM Users:

    Go to the IAM console.
    Select the user you want to enable MFA for.
    Choose the "Security credentials" tab.
    Click "Manage" next to "Assigned MFA device".
    Follow the instructions to assign a virtual MFA device.