# CDKTF Project Setup Guide

This guide will help you gather the necessary AWS values required to configure and deploy Zilla Plus IOT Ingest and Control using CDKTF.

## Prerequisites

1. Be subscribed to [Zilla Plus for Amazon MSK](https://aws.amazon.com/marketplace/pp/prodview-jshnzslazfm44).
1. [Install Node.js](https://nodejs.org/en/download/package-manager).
1. [Install Terraform](https://developer.hashicorp.com/terraform/tutorials/aws-get-started/install-cli).
1. [Install CDKTF](https://developer.hashicorp.com/terraform/tutorials/cdktf/cdktf-install).
1. [Install AWS CLI](https://docs.aws.amazon.com/cli/latest/userguide/install-cliv2.html).
1. Configure AWS CLI: Run `aws configure` and follow the prompts to set up your AWS credentials.
1. Set your aws region: `aws configure set region us-east-1`
1. Verify your region and credentials: `aws configure list`

    ```text
          Name                    Value             Type    Location
          ----                    -----             ----    --------
       profile                <not set>             None    None
    access_key     ****************XXXX              env
    secret_key     ****************XXXX              env
        region                us-east-1              env    ['AWS_REGION', 'AWS_DEFAULT_REGION']
    ```

## (optional) Create an example MSK cluster

If you don't have an existing MSK cluster you can use our example MSK deployment with basic configuration and SASL/SCRAM authentication setup.
Use `cdktf deploy` inside the `example-cluster` folder to deploy the example MSK cluster.
Note the `mskClusterName` from the outputs as you'll need this later.

## Variables

### 1. MSK Cluster Name (`msk_cluster_name`)

You need the name of your MSK cluster.

List all MSK clusters:

```bash
aws kafka list-clusters --query 'ClusterInfoList[*].[ClusterName,ClusterArn]' --output table
```

Note down the name (ClusterName) of the desired MSK cluster.

### 2. MSK Access Credentials Name (`msk_access_credentials_name`)

Provide the Secret Name that is associated with your MSK cluster. If you use our provided example cluster, there is already a secret assicated with the cluster called `AmazonMSK_alice`.

### 3. Public TLS Certificate Key (`public_tls_certificate_key`)

You need the ARN of the Secrets Manager secret that contains your public TLS certificate private key.

List all secrets in Secrets Manager:

```bash
aws secretsmanager list-secrets --query 'SecretList[*].[Name,ARN]' --output table
```

Find and note down the ARN of the secret that contains your public TLS certificate private key.

### 4. Zilla Plus Role (`zilla_plus_role`)

By default the deployment creates the Zilla Plus Role with the necessary roles and policies. If you want, you can specify your own role by setting `CREATE_ZILLA_PLUS_ROLE` environment variable to `false` and adding `zilla_plus_role` to you `terraform.tfvars` file.

List all IAM roles:

```bash
aws iam list-roles --query 'Roles[*].[RoleName,Arn]' --output table
```

Note down the role name (RoleName) of the desired IAM role.

### 5. Zilla Plus Security Groups (`zilla_plus_security_groups`)

By default the deployment creates the Zilla Plus Security Group with the necessary ports to be open. If you want, you can specify your own security group by setting `CREATE_ZILLA_PLUS_SECURITY_GROUP` environment variable to `false` and adding `zilla_plus_security_groups` to you `terraform.tfvars` file.

List all security groups:

```bash
aws ec2 describe-security-groups --query 'SecurityGroups[*].[GroupId, GroupName]' --output table
```

Note down the security group IDs (GroupId) of the desired security groups.

### 6. Zilla Plus Capacity (`zilla_plus_capacity`)

This variable defines the initial number of Zilla Plus instances.

#### Default Value

- Default: `2`

### 7. Public TCP Port (`public_tcp_port`)

This variable defines the public port number to be used by Kafka clients.

Default Value

- Default: `8883`

## Kafka topics

By default, the deployment creates the provided Kafka topics required by Zilla Plus. To disable this set the environment variable `MQTT_KAFKA_TOPIC_CREATION_DISABLED` to `true`.

### 8. Kafka Topic for MQTT Sessions (kafka_topic_mqtt_sessions)

This variable defines the Kafka topic storing MQTT sessions with a cleanup policy set to "compact".

Default Value

- Default: `mqtt-sessions`

### 9. Kafka Topic for MQTT Messages (`kafka_topic_mqtt_messages`)

This variable defines the Kafka topic storing MQTT messages with a cleanup policy set to "delete".

Default Value

- Default: `mqtt-messages`

### 10. Kafka Topic for MQTT Retained Messages (kafka_topic_mqtt_retained)

This variable defines the Kafka topic storing MQTT retained messages with a cleanup policy set to "compact".

Default Value

- Default: `mqtt-retained`

## Optional Features

### SSH Key Access (key_name)

To enable SSH access to the instances, set the environment variable `SSH_KEY_ENABLED` to `true`. You will also need the name of an existing EC2 KeyPair.

1. List all EC2 KeyPairs:

```bash
aws ec2 describe-key-pairs --query 'KeyPairs[*].[KeyName]' --output table
```

Note down the KeyPair name (KeyName) you want to use.

### CloudWatch Integration

By default CloudWatch metrics and logging is enabled. To disable CloudWatch logging and metrics, set the environment variable `CLOUDWATCH_DISABLED` to `true`.

You can create or use existing log groups and metric namespaces in CloudWatch.

By default, the deployment creates a CloudWatch Log Groups and Custom Metrics Namespace.
If you want to define your own, follow these steps.

#### List All CloudWatch Log Groups (cloudwatch_logs_group)

```bash
aws logs describe-log-groups --query 'logGroups[*].[logGroupName]' --output table
```

This command will return a table listing the names of all the log groups in your CloudWatch.
In your `terraform.tfvars` file add the desired CloudWatch Logs Group for variable name `cloudwatch_logs_group`

#### List All CloudWatch Custom Metric Namespaces (cloudwatch_metrics_namespace)

```bash
aws cloudwatch list-metrics --query 'Metrics[*].Namespace' --output text | tr '\t' '\n' | sort | uniq | grep -v '^AWS'
```

In your `terraform.tfvars` file add the desired CloudWatch Metrics Namespace for variable name `cloudwatch_metrics_namespace`

## Deploy stack using Terraform

### 1. Install Project Dependencies

Install the necessary dependencies specified in the generated `package.json` file:

```bash
npm install
```

### 2. Synthesize the Terraform Configuration

First, you need to synthesize the Terraform configuration from the CDKTF code.

Navigate to the CDKTF project directory.

Run the following command to synthesize the configuration:

```bash
cdktf synth
```

This command will generate the necessary Terraform JSON configuration files in the cdktf.out directory.

### 4. Navigate to the Terraform Configuration Folder

After synthesizing the configuration, navigate to the folder where the Terraform JSON output is located:

```bash
cd cdktf.out/stacks/iot-ingest-and-control
```

Speicfy the necessary variables based on your setup.

### 5. Run terraform init and plan

```bash
terraform init
```

```bash
terraform plan
```

This command will show the execution plan, and you will be prompted to provide necessary input variables. You can manually enter these values when prompted, or use a `.tfvars` file to provide them.

### 6. Apply the Terraform Plan

Once you have reviewed the plan and provided the necessary inputs, apply the plan to deploy the resources:

```bash
terraform apply
```

### 7. Configure Global DNS

This ensures that any new Kafka brokers added to the cluster can still be reached via the Zilla proxy.
When using a wildcard DNS name for your own domain, such as `*.example.aklivity.io` then the DNS entries are setup in your DNS provider.
After deploying the stack, check the outputs, where you can find the NetworkLoadBalancer DNS.
`NetworkLoadBalancerOutput = "network-load-balancer-******.elb.us-east-1.amazonaws.com"`
Lookup the IP addresses of your load balancer using `nslookup` and the DNS of the NetworkLoadBalancer.

```bash
nslookup network-load-balancer-******.elb.us-east-1.amazonaws.com
```

For testing purposes you can edit your local /etc/hosts file instead of updating your DNS provider. For example:

```bash
X.X.X.X  mqtt.example.aklivity.io
```

### 8. Test the Zilla Plus MQTT broker

If you added `mqtt.example.aklivity.io` as the domain, open a terminal and subscribe to topic filter `sensors/#`

```bash
 mosquitto_sub -V '5' --url mqtts://mqtt.example.aklivity.io/sensors/# -p 8883 -d
```

Open another terminal and publish to topic `sensors/one`.

```bash
mosquitto_pub -V '5' --url mqtts://mqtt.example.aklivity.io/sensors/one -p 8883 -m "Hello, World" -d
```
