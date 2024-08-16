# IOT Ingest and Control Terraform deploy via CDKTF

This guide will help you gather the necessary AWS values required to configure and deploy Zilla Plus IOT Ingest and Control using CDKTF.

## Prerequisites

1. Be subscribed to [Zilla Plus for Amazon MSK](https://aws.amazon.com/marketplace/pp/prodview-jshnzslazfm44).
1. [Install Node.js](https://nodejs.org/en/download/package-manager).
1. [Install Terraform](https://developer.hashicorp.com/terraform/tutorials/aws-get-started/install-cli).
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

If you don't have an existing MSK cluster you can use our example MSK deployment with basic configuration and Unauthorized access. Follow the instructions inside the [example-cluster](../example-cluster/README.md) folder to deploy the example MSK cluster. Note the `mskClusterName` from the outputs as you'll need this later.

## Required Terraform Variables

You can set these variable values in your `terraform.tfvars` file. To create a `.tfvars` from the example file run:

```bash
cp terraform.tfvars.example terraform.tfvars
```

### `msk_cluster_name`: MSK Cluster Name

To get a list all MSK clusters run:

```bash
aws kafka list-clusters --query 'ClusterInfoList[*].[ClusterName,ClusterArn]' --output table
```

Use the `ClusterName` of your desired MSK cluster for this variable.

### `msk_access_credentials_name`: MSK access credentials Secret Name

Provide the Secret Name that is associated with your MSK cluster. If you use our provided example cluster, there is already a secret associated with the cluster called `AmazonMSK_alice`.

### `public_tls_certificate_key`: Public TLS Certificate Key

You need the ARN of the Secrets Manager secret that contains your public TLS certificate private key.

List all secrets in Secrets Manager:

```bash
aws secretsmanager list-secrets --query 'SecretList[*].[Name,ARN]' --output table
```

Find and note down the ARN of the secret that contains your public TLS certificate private key.

### `zilla_plus_capacity`: Zilla Plus Capacity

> Default: `2`

This variable defines the initial number of Zilla Plus instances.

### `zilla_plus_instance_type`: Zilla Plus EC2 Instance Type

> Default: `t3.small`

This variable defines the initial number of Zilla Plus instances.

### `public_port`: Public TCP Port

> Default: `8883`

This variable defines the public port number to be used by MQTT clients.

## Optional Features

These features all have default values and can be configured using environment variables and terraform variables. If you don't plan to configure any of these features you can skip this section and go to the [Deploy stack using Terraform](#deploy-stack-using-terraform) section.

### Environment Variables

You can set these variable values in your runtime environment or with a `.env` file. If you don't plan on modifying any of the environment variable defaults you can skip this step.

Create a `.env` file from the example file.

```bash
cp .env.example .env
```

### Kafka topics

By default, the deployment creates the provided Kafka topics required by Zilla Plus. To disable this set the environment variable `MQTT_KAFKA_TOPIC_CREATION_DISABLED` to `true` and set the `kafka_topic_mqtt_sessions`, `kafka_topic_mqtt_messages`, and `kafka_topic_mqtt_retained` in your `terraform.tfvars` file.

#### `kafka_topic_mqtt_sessions`: Kafka Topic for MQTT Sessions

> Default: `mqtt-sessions`

This variable defines the Kafka topic storing MQTT sessions with a cleanup policy set to "compact".

#### `kafka_topic_mqtt_messages`: Kafka Topic for MQTT Messages

> Default: `mqtt-messages`

This variable defines the Kafka topic storing MQTT messages with a cleanup policy set to "delete".

#### `kafka_topic_mqtt_retained`: Kafka Topic for MQTT Retained Messages

> Default: `mqtt-retained`

This variable defines the Kafka topic storing MQTT retained messages with a cleanup policy set to "compact".

### Custom Zilla Plus Role

By default the deployment creates the Zilla Plus Role with the necessary roles and policies. If you want, you can specify your own role by setting `CREATE_ZILLA_PLUS_ROLE` environment variable to `false` and adding `zilla_plus_role` to your `terraform.tfvars` file.

List all IAM roles:

```bash
aws iam list-roles --query 'Roles[*].[RoleName,Arn]' --output table
```

Note down the role name `RoleName` of the desired IAM role.

### Custom Zilla Plus Security Groups

By default the deployment creates the Zilla Plus Security Group with the necessary ports to be open. If you want, you can specify your own security group by setting `CREATE_ZILLA_PLUS_SECURITY_GROUP` environment variable to `false` and adding `zilla_plus_security_groups` to your `terraform.tfvars` file.

List all security groups:

```bash
aws ec2 describe-security-groups --query 'SecurityGroups[*].[GroupId, GroupName]' --output table
```

Note down the security group IDs (GroupId) of the desired security groups.

### Disable CloudWatch Integration

By default CloudWatch metrics and logging is enabled. To disable CloudWatch logging and metrics, set the `CLOUDWATCH_DISABLED` environment variable to `true`.

You can create or use existing log groups and metric namespaces in CloudWatch.

By default, the deployment creates a CloudWatch Log Groups and Custom Metrics Namespace.
If you want to define your own, follow these steps.

#### List All CloudWatch Log Groups

```bash
aws logs describe-log-groups --query 'logGroups[*].[logGroupName]' --output table
```

This command will return a table listing the names of all the log groups in your CloudWatch.
In your `terraform.tfvars` file add the desired CloudWatch Logs Group for variable name `cloudwatch_logs_group`

#### List All CloudWatch Custom Metric Namespaces

```bash
aws cloudwatch list-metrics --query 'Metrics[*].Namespace' --output text | tr '\t' '\n' | sort | uniq | grep -v '^AWS'
```

In your `terraform.tfvars` file add the desired CloudWatch Metrics Namespace for variable name `cloudwatch_metrics_namespace`

### Enable SSH Access

To enable SSH access to the instances, set the `SSH_KEY_ENABLED` environment variable to `true`. You will also need the name of an existing EC2 KeyPair to set the `zilla_plus_ssh_key` terraform variable.

List all EC2 KeyPairs:

```bash
aws ec2 describe-key-pairs --query 'KeyPairs[*].[KeyName]' --output table
```

Note down the KeyPair name `KeyName` you want to use.

## Deploy stack using Terraform

### Install Project Dependencies

Install the node.js dependencies specified in the `package.json` file:

```bash
npm install
```

### Synthesize the Terraform Configuration

First, you need to synthesize the Terraform configuration from the CDKTF code.

Navigate to the CDKTF project directory.

Run the following command to to generate providers in a `.gen` folder:

```bash
npm run get
```

Run the following command to synthesize the configuration:

```bash
npm run synth
```

This command will generate the necessary Terraform JSON configuration files in the cdktf.out directory.

### Run terraform init and apply

After synthesizing the configuration you can use `terraform` to deploy zilla.

Move your `.tfvars` file into the the generated dir or you can manually enter these values when prompted, or use a .tfvars file to provide them.

```bash
cp terraform.tfvars cdktf.out/stacks/iot-ingest-and-control/terraform.tfvars
```

Initialize terraform.

```bash
terraform -chdir=cdktf.out/stacks/iot-ingest-and-control init
```

Apply the plan, review the resources to be create, and confirm to deploy the resources:

```bash
terraform -chdir=cdktf.out/stacks/iot-ingest-and-control apply
```

### Configure Global DNS

This ensures that any new Kafka brokers added to the cluster can still be reached via the Zilla proxy. When using a wildcard DNS name for your own domain, such as `*.example.aklivity.io` then the DNS entries are setup in your DNS provider. After deploying the stack, check the outputs, where you can find the NetworkLoadBalancer DNS. `NetworkLoadBalancerOutput = "network-load-balancer-******.elb.us-east-1.amazonaws.com"` Lookup the IP addresses of your load balancer using `nslookup` and the DNS of the NetworkLoadBalancer.

```bash
nslookup network-load-balancer-******.elb.us-east-1.amazonaws.com
```

For testing purposes you can edit your local /etc/hosts file instead of updating your DNS provider. For example:

```bash
X.X.X.X  mqtt.example.aklivity.io
```

### Test the Zilla Plus MQTT broker

If you added `mqtt.example.aklivity.io` as the domain, open a terminal and subscribe to topic filter `sensors/#`

```bash
 mosquitto_sub -V '5' --url mqtts://mqtt.example.aklivity.io/sensors/# -p 8883 -d
```

Open another terminal and publish to topic `sensors/one`.

```bash
mosquitto_pub -V '5' --url mqtts://mqtt.example.aklivity.io/sensors/one -p 8883 -m "Hello, World" -d
```
