# IOT Ingest and Control deploy via CDK

This guide will help you gather the necessary AWS values required to configure and deploy Zilla Plus IOT Ingest and Control using CDK.

## Prerequisites

1. Be subscribed to [Zilla Plus for Amazon MSK](https://aws.amazon.com/marketplace/pp/prodview-jshnzslazfm44).
1. [Install Node.js](https://nodejs.org/en/download/package-manager).
1. [Install AWS CDK](https://docs.aws.amazon.com/cdk/v2/guide/getting_started.html).
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

If you don't have an existing MSK cluster you can use our example MSK deployment with basic configuration and SASL/SCRAM access. Follow the instructions inside the [example-cluster](../example-cluster/README.md) folder to deploy the example MSK cluster. Note the `MskClusterArn` from the outputs as you'll need this later. You will need to set the MSK client auth method variable to the desired one that is set up for the MSK cluster.

## Required CDK Context Variables

You can set these variables in your `context` in `cdk.json` file under `zilla-plus` object.

### `vpcId`: VPC ID
The VPC ID where the MSK cluster lives. The stack will add Public Subnets and Internet Gateway and run Zilla Plus on the provided VPC.

```bash
aws ec2 describe-subnets --subnet-ids $(aws kafka describe-cluster --cluster-arn <msk-cluster-arn> --query "ClusterInfo.BrokerNodeGroupInfo.ClientSubnets[0]" --output text) --query "Subnets[0].VpcId" --output text
```


### `msk` related variables

```json
    "msk":
    {
      "bootstrapServers": "<your SASL/SCRAM MSK Bootstrap Servers>",
      "credentialsSecretName": "<Secret Name associated with your MSK cluster>"  
    },
```

#### `bootstrapServers`: MSK Bootstrap Servers

To get the bootstrap servers of the MSK cluster run:

```bash
aws kafka get-bootstrap-brokers \
    --cluster-arn arn:aws:kafka:us-east-1:445711703002:cluster/my-msk-cluster/83bf3e6e-c31d-4a16-9c0e-3584e845d2d7-20 \
    --query '{BootstrapBrokerStringSaslScram: BootstrapBrokerStringSaslScram}' \
    --output table
```

Use the `SASL/SCRAM Bootstrap Server` to set the `msk.bootstrapServers` variable.

#### `credentialsSecretName`: MSK Credentials Secret Name

Provide the Secret Name that is associated with your MSK cluster. If you use our provided example cluster, there is already a secret associated with the cluster called `AmazonMSK_alice`.

List all secrets ub Secrets Manager that can be associated with MSK:

```bash
aws secretsmanager list-secrets --query "SecretList[?starts_with(Name, 'AmazonMSK_')].Name" --output table
```

### `publicTlsCertificateKey`: Public TLS Certificate Key

You need the ARN of the Secrets Manager secret that contains your public TLS certificate private key.

List all secrets in Secrets Manager:

```bash
aws secretsmanager list-secrets --query 'SecretList[*].[Name,ARN]' --output table
```

Find and note down the ARN of the secret that contains your public TLS certificate private key.

### `capacity`: Zilla Plus Capacity

> Default: `2`

This variable defines the initial number of Zilla Plus instances.

### `instanceType`: Zilla Plus EC2 Instance Type

> Default: `t3.small`

This variable defines the initial number of Zilla Plus instances.

### `publicPort`: Public TCP Port

> Default: `8883`

This variable defines the public port number to be used by MQTT clients.

## Optional Features

These features all have default values and can be configured using cdk context variables. If you don't plan to configure any of these features you can skip this section and go to the [Deploy stack using CDK](#deploy-stack-using-cdk) section.

### Internet Gateway ID

If you already have an Internet Gateway in the MSK's VPN it should be provided via the `igwId` context variable in your `cdk.json` under `zilla-plus` object. If not set the deployment will attempt to create on in the VPC.

To query the igwId of your MSK's VPN use the following command:
```bash
VPC_ID=$(aws kafka describe-cluster --cluster-arn <msk-cluster-arn> --query "ClusterInfo.VpcConfig.VpcId" --output text)
aws ec2 describe-internet-gateways --filters "Name=attachment.vpc-id,Values=$VPC_ID" --query "InternetGateways[0].InternetGatewayId" --output text
```

### Kafka topics

```json
      "topics":
      {
        "sessions": "<your sessions topic>",
        "messages": "<your messages topic>",
        "retained": "<your retained topic>"
      }
```

By default, the deployment creates the provided Kafka topics required by Zilla Plus. To disable this set the context variable `kafkaTopicCreationDisabled` to `true` and set the `sessions`, `messages`, and `retained` context variables in your `cdk.json` file under `zilla-plus` and `topics` object.

#### `topics.sessions`: Kafka Topic for MQTT Sessions

> Default: `mqtt-sessions`

This variable defines the Kafka topic storing MQTT sessions with a cleanup policy set to "compact".

#### `topics.messages`: Kafka Topic for MQTT Messages

> Default: `mqtt-messages`

This variable defines the Kafka topic storing MQTT messages with a cleanup policy set to "delete".

#### `topics.retained`: Kafka Topic for MQTT Retained Messages

> Default: `mqtt-retained`

This variable defines the Kafka topic storing MQTT retained messages with a cleanup policy set to "compact".

### Custom Zilla Plus Role

By default the deployment creates the Zilla Plus Role with the necessary roles and policies. If you want, you can specify your own role by setting `roleName` context variable in your `cdk.json` under `zilla-plus` object.

List all IAM roles:

```bash
aws iam list-roles --query 'Roles[*].[RoleName,Arn]' --output table
```

Note down the role name `RoleName` of the desired IAM role.

### Custom Zilla Plus Security Groups

By default the deployment creates the Zilla Plus Security Group with the necessary ports to be open. If you want, you can specify your own security group by setting `securityGroups` context variable in your `cdk.json`.

List all security groups:

```bash
aws ec2 describe-security-groups --query 'SecurityGroups[*].[GroupId, GroupName]' --output table
```

Note down the security group IDs (GroupId) of the desired security groups.

#### CloudWatch Integration

```json
    "cloudwatch":
    {
        "disable": false,
        "logGroupName": "<your cloudwatch log group name>",
        "metricsNamespace": "<your cloudwatch metrics namespace>"
    }
```

By default CloudWatch metrics and logging is enabled. To disable CloudWatch logging and metrics, set the `cloudwatchDisabled` context variable to `true`.

You can create or use existing log groups and metric namespaces in CloudWatch.

By default, the deployment creates a CloudWatch Log Groups and Custom Metrics Namespace.
If you want to define your own, follow these steps.

#### List All CloudWatch Log Groups

```bash
aws logs describe-log-groups --query 'logGroups[*].[logGroupName]' --output table
```

This command will return a table listing the names of all the log groups in your CloudWatch.
In your `cdk.json` file add the desired CloudWatch Logs Group for variable name `logGroupName` under `zilla-plus` object in the `cloudwatch` variables section.

#### List All CloudWatch Custom Metric Namespaces

```bash
aws cloudwatch list-metrics --query 'Metrics[*].Namespace' --output text | tr '\t' '\n' | sort | uniq | grep -v '^AWS'
```

In your `cdk.json` file add the desired CloudWatch Metrics Namespace for variable name `metricsNamespace` under `zilla-plus` object in the `cloudwatch` variables section.

### Enable SSH Access

To enable SSH access to the instances you will need the name of an existing EC2 KeyPair to set the `sshKey` context variable.

List all EC2 KeyPairs:

```bash
aws ec2 describe-key-pairs --query 'KeyPairs[*].[KeyName]' --output table
```

Note down the KeyPair name `KeyName` you want to use.

## Deploy stack using CDK

### Install Project Dependencies

Install the node.js dependencies specified in the `package.json` file:

```bash
npm install
```

### Synthesizing the CloudFormation Template

Run the following command to synthesize your stack into a CloudFormation template:

```bash
cdk synth
```

This generates the cdk.out directory containing the synthesized CloudFormation template.

### Bootstrap the environment (if needed)

If this is your first time deploying in a specific AWS environment, bootstrap it:

```bash
cdk bootstrap
```

### Deploy the stack
Deploy your resources to AWS:


```bash
cdk deploy
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
