# Wazuh Setup and Configuration for AWS EC2

This guide provides detailed steps to deploy Wazuh server and agents on AWS EC2 instances to comply with NIST SP 800-171 controls for Audit and Accountability.

## Table of Contents
- [Wazuh Setup and Configuration for AWS EC2](#wazuh-setup-and-configuration-for-aws-ec2)
  - [Table of Contents](#table-of-contents)
  - [Step 1: Launch an EC2 Instance for Wazuh Server](#step-1-launch-an-ec2-instance-for-wazuh-server)
  - [Step 2: Install and Configure Wazuh Server](#step-2-install-and-configure-wazuh-server)
  - [Step 3: Install and Configure Wazuh Agent on Another EC2 Instance](#step-3-install-and-configure-wazuh-agent-on-another-ec2-instance)
  - [Step 4: Verify Wazuh Server and Agent Connection](#step-4-verify-wazuh-server-and-agent-connection)
  - [Step 5: Configure Audit and Accountability Controls](#step-5-configure-audit-and-accountability-controls)

## Step 1: Launch an EC2 Instance for Wazuh Server

1. **Log in to AWS Management Console**.
2. **Launch a new EC2 instance**:
    - **Choose an Amazon Machine Image (AMI)**:
        - For this example, use Ubuntu Server 20.04 LTS (HVM), SSD Volume Type.
    - **Choose an Instance Type**:
        - Select an instance type. A `t2.medium` instance type is a good start.
    - **Configure Instance**:
        - Number of instances: 1
        - Network: Select your VPC.
        - Subnet: Select your subnet.
    - **Add Storage**:
        - Use the default settings.
    - **Configure Security Group**:
        - Add rules to allow traffic to necessary ports:
            - HTTP: 80
            - HTTPS: 443
            - Custom TCP Rule: 1514 (Wazuh agent to Wazuh server communication)
            - Custom TCP Rule: 1515 (Wazuh agent to Wazuh server communication)
            - Custom TCP Rule: 55000 (Wazuh agent to Wazuh server communication)
            - SSH: 22 (For SSH access)
    - **Launch the instance**.

3. **Connect to your EC2 instance**:
    ```sh
    ssh -i /path/to/your-key.pem ubuntu@your-ec2-instance-ip
    ```

## Step 2: Install and Configure Wazuh Server

1. **Install Docker**:
    ```sh
    sudo apt-get update
    sudo apt-get install -y docker.io
    ```

2. **Deploy Wazuh Server using Docker**:
    ```sh
    sudo docker run -d --name wazuh -p 55000:55000 -p 1514:1514/udp -p 1515:1515 wazuh/wazuh
    ```

3. **Set up Wazuh API**:
    - Access the Wazuh container:
        ```sh
        sudo docker exec -it wazuh /bin/bash
        ```
    - Start the Wazuh API:
        ```sh
        /var/ossec/bin/ossec-control start
        ```
    - Create a Wazuh API user:
        ```sh
        /var/ossec/bin/wazuh-api-util manage-api create-user --username wazuh-admin --password MyPassword --role=administrator
        ```

## Step 3: Install and Configure Wazuh Agent on Another EC2 Instance

1. **Launch another EC2 instance** for the Wazuh agent following similar steps as above.

2. **Connect to the new EC2 instance**:
    ```sh
    ssh -i /path/to/your-key.pem ubuntu@your-agent-ec2-instance-ip
    ```

3. **Download and install Wazuh Agent**:
    ```sh
    curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | sudo apt-key add -
    echo "deb https://packages.wazuh.com/4.x/apt/ stable main" | sudo tee /etc/apt/sources.list.d/wazuh.list
    sudo apt-get update
    sudo apt-get install wazuh-agent
    ```

4. **Configure Wazuh Agent**:
    - Edit the Wazuh agent configuration file to point to your Wazuh server:
        ```sh
        sudo nano /var/ossec/etc/ossec.conf
        ```
    - Find the `<server>` section and update it:
        ```xml
        <server>
          <address>Your_Wazuh_Server_IP</address>
        </server>
        ```

5. **Start Wazuh Agent**:
    ```sh
    sudo systemctl start wazuh-agent
    sudo systemctl enable wazuh-agent
    ```

## Step 4: Verify Wazuh Server and Agent Connection

1. **Login to Wazuh web interface**:
    - Access `https://your-wazuh-server-ip` in your web browser.
    - Login with the credentials you set up earlier.

2. **Verify agent registration**:
    - In the Wazuh web interface, navigate to the "Agents" tab.
    - Ensure the Wazuh agent appears in the list and is active.
    
## Step 5: Configure Audit and Accountability Controls

Use the provided code and functions to implement the audit and accountability controls within your application.

### Audit and Accountability Functions
