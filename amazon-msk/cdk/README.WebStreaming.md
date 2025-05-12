# Web Streaming deploy via CDK

This guide will help you gather the necessary AWS values required to configure and deploy Zilla Plus Web Streaming using CDK.

## Prerequisites

1. Deploy [`MskProvisionedCluster`](README.MskProvisionedCluster.md) stack via CDK
2. Subscribe to [Zilla Plus for Amazon MSK].
3. [Install Node.js].
4. [Install AWS CDK].
5. [Install AWS CLI].
6. Configure AWS CLI: Run `aws configure` and follow the prompts to set up your AWS credentials.
7. Set your aws region: `aws configure set region us-east-1`
8. Verify your region and credentials: `aws configure list`

   ```text
         Name                    Value             Type    Location
         ----                    -----             ----    --------
      profile                <not set>             None    None
   access_key     ****************XXXX              env
   secret_key     ****************XXXX              env
       region                us-east-1              env    ['AWS_REGION', 'AWS_DEFAULT_REGION']
   ```

9. Verify that your MSK Provisioned cluster Security Group allows inbound traffic for port `9096` (SASL).

## List the inbound rules for Security Group

```bash
aws ec2 describe-security-groups \
  --group-ids $(aws kafka list-clusters-v2 \
    --cluster-type PROVISIONED \
    --query "ClusterInfoList[?ClusterArn=='<msk-provisioned-arn>'].Provisioned.BrokerNodeGroupInfo.SecurityGroups[]" \
    --output text) \
  --query "SecurityGroups[].IpPermissions" \
  --output json
```

If the Security Groups do not allow inbound traffic for port `9096`, then make sure to allow that and re-verify.

## Configure the stack

You can set these `context` variables via `cdk.context.json`, under `WebStreaming` object.

If your local `cdk.context.json` file does not already exist, copy the example to get started.

```bash
cp -n examples/cdk.context.WebStreaming.json cdk.context.json
```

Then, further modify `cdk.context.json` based on the context variable descriptions below.

### `vpcId`: VPC ID

The VPC ID where the MSK Provisioned cluster was created.

```bash
aws ec2 describe-subnets \
  --subnet-ids $(aws kafka describe-cluster \
    --cluster-arn <msk-cluster-arn> \
    --query "ClusterInfo.BrokerNodeGroupInfo.ClientSubnets[0]" \
    --output text) \
  --query "Subnets[0].VpcId" \
  --output json
```

Set the `VPC ID` for Zilla Plus via `cdk.context.json`, in the `WebStreaming` `vpcId` variable.

#### `subnetIds`: Subnet IDs

The subnet IDs for your Zilla Plus deployment, network reachable to your MSK Provisioned cluster.

> Default: `PUBLIC` subnets in VPC

```bash
aws kafka list-clusters-v2 \
  --cluster-type PROVISIONED \
  --query "ClusterInfoList[?ClusterArn=='<msk-cluster-arn>'].Provisioned.BrokerNodeGroupInfo.ClientSubnets[]" \
  --output json
```

Set the Subnet IDs for Zilla Plus via `cdk.context.json`, in the `WebStreaming` `subnetIds` variable.

### `msk` related variables

```json
    "msk":
    {
      "servers": "<your SASL/SCRAM MSK Bootstrap Servers>",
      "credentials":
      {
        "sasl": "<Secret Name associated with your MSK cluster>"
      }
    },
```

#### `servers`: MSK Bootstrap Servers

To get the bootstrap servers of the MSK cluster run:

```bash
aws kafka get-bootstrap-brokers \
    --cluster-arn <msk-cluster-arn> \
    --query '{BootstrapBrokerStringSaslScram: BootstrapBrokerStringSaslScram}' \
    --output table
```

Use the `SASL/SCRAM Bootstrap Server` to set the `msk.servers` variable.

#### `credentials.sasl`: MSK Credentials Secret Name

Provide the Secret Name that is associated with your MSK cluster. If you use our provided example cluster, there is already a secret associated with the cluster called `AmazonMSK_alice`.

List all secrets in Secrets Manager that can be associated with MSK:

```bash
aws secretsmanager list-secrets --query "SecretList[?starts_with(Name, 'AmazonMSK_')].Name" --output table
```

### `public` Zilla Plus variables

```json
    "public":
    {
      "servers": "<your public wildcard servers including port>",
      "certificate": "<your public tls certificate key ARN>"
    }
```

#### `servers`: Public wildcard servers including port

This variable defines the public servers to be used by MQTT clients in the format `hostname:port`.
The public server name should match the custom domain wildcard DNS pattern of the public TLS certificate.

Set the public server for Zilla Plus via `cdk.context.json`, in the `WebStreaming` `public` `servers` variable.

#### `certificate`: Public TLS Certificate Key

You need the ARN of either the Certificate Manager certificate or the Secrets Manager secret that contains your TLS certificate private key.

List all certificates in Certificate Manager:

```bash
aws acm list-certificates \
  --certificate-statuses ISSUED \
  --query 'CertificateSummaryList[*].[DomainName,CertificateArn]' \
  --output table
```

Set the AWS Certificate Manager ARN for Zilla Plus via `cdk.context.json`, in the `WebStreaming` `public` `certificate` variable.

Note: If you specify an AWS Certificate Manager certificate ARN, then Zilla Plus will automatically enable AWS Nitro Enclaves for Zilla Plus and use [ACM for Nitro Enclaves] to install the certificate and seamlessly replace expiring certificates.

List all secrets in Secrets Manager:

```bash
aws secretsmanager list-secrets \
  --query 'SecretList[*].[Name,ARN]' \
  --output table
```

Alternatively, set the AWS Secrets Manager ARN for Zilla Plus via `cdk.context.json`, in the `WebStreaming` `public` `certificate` variable.

If using AWS Secrets Manager to store the TLS certificate, the secret value should contain a private key and full certificate chain in text-based PEM format.

For example, the secret value would be of the form:

```text
-----BEGIN PRIVATE KEY-----
...
-----END PRIVATE KEY-----
-----BEGIN CERTIFICATE-----
...
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
...
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
...
-----END CERTIFICATE-----
```

### `capacity`: Zilla Plus Capacity

> Default: `2`

This variable defines the initial number of Zilla Plus instances.

Optionally override the default initial number of instances for Zilla Plus via `cdk.context.json`, in the `WebStreaming` `capacity` variable.

### `instanceType`: Zilla Plus EC2 Instance Type

> Default: `c6i.xlarge`

This variable defines the type of Zilla Plus instances.

Optionally override the default instance type for Zilla Plus via `cdk.context.json`, in the `WebStreaming` `instanceType` variable.


### `mappings`: Kafka Topic Mappings

```json
    "mappings":
    [
        {"topic": "<your kafka topic>"},
        {"topic": "<your kafka topic>", "path": "<your custom path>"}
    ]
```

This array variable defines the Kafka topics exposed through REST and SSE. If `path` is not specified, the topic will be exposed on `/<topic>`.
To enable a custom path for the Kafka topic, set the `path` field to the path where the Kafka topic should be exposed.


### `roleName`: Zilla Plus EC2 Instance Assumed Role

> Default: (generated)

By default the deployment creates the Zilla Plus Role with the necessary roles and policies. If you prefer, you can specify your own role instead.

List all IAM roles:

```bash
aws iam list-roles \
  --query 'Roles[*].[RoleName,Arn]' \
  --output table
```

Optionally override the assumed role (RoleName) for Zilla Plus via `cdk.context.json`, in the `WebStreaming` `roleName` variable.

### `securityGroup`: Zilla Plus EC2 Instance Security Group

> Default: (generated)

By default the deployment creates the Zilla Plus Security Group with the necessary ports to be open. If you prefer, you can specify your own security group instead.

List all security groups:

```bash
aws ec2 describe-security-groups \
  --query 'SecurityGroups[*].[GroupId, GroupName]' \
  --output table
```

Optionally override the security group IDs (GroupId) for Zilla Plus via `cdk.context.json`, in the `WebStreaming` `securityGroup` variable.

### `cloudwatch` Zilla Plus variables

> Default: (disabled)

```json
    "cloudwatch":
    {
        "logs":
        {
            "group": "<your cloudwatch log group name>"
        },
        "metrics":
        {
            "namespace": "<your cloudwatch metrics namespace>"
        }
    }
```

CloudWatch logging is enabled when you specify a log group name.
CloudWatch metrics is enabled when you specify a metrics namespace.

#### List All CloudWatch Log Groups

```bash
aws logs describe-log-groups \
  --query 'logGroups[*].[logGroupName]' \
  --output table
```

This command returns a table listing the names of all the log groups in your CloudWatch in the current AWS region.

Optionally specify the CloudWatch Logs Group for Zilla Plus via `cdk.context.json`, in the `WebStreaming` `cloudwatch` `logs` `group` variable.

#### List All CloudWatch Custom Metric Namespaces

```bash
aws cloudwatch list-metrics \
  --query "Metrics[?\!contains(Namespace, 'AWS')].Namespace" \
  --output table \
| sort \
| uniq
```

Optionally specify the CloudWatch Metrics Namespace for Zilla Plus via `cdk.context.json`, in the `WebStreaming` `cloudwatch` `metrics` `namespace` variable.

### Enable JWT Access Tokens

To enable the JWT authentication and API access control, you need to provide the `jwt` context variable. You will also need to set the JWT Issuer (`issuer`), JWT Audience (`audience`) and JWKS URL (`keys_url`) context variable inside the `jwt` object. Example:

```json
    "jwt": {
      "issuer" : "https://auth.example.com",
      "audience": "https://api.example.com",
      "keysUrl": "https://{yourDomain}/.well-known/jwks.json"
    }
```

### Enable Glue Schema Registry

To enable the Glue Schema Registry for schema fetching, set the context variable `glue` `registry` to the name of the Glue Registry.

1. List all Glue Registries:

```bash
aws glue list-registries --query 'Registries[*].[RegistryName]' --output table
```

Note down the Glue Registry name (RegistryName) you want to use.

### Enable SSH Access

> Default: (none)

To enable SSH access to the instances you will need the name of an existing EC2 KeyPair.

#### List all EC2 KeyPairs

```bash
aws ec2 describe-key-pairs \
  --query 'KeyPairs[*].[KeyName]' \
  --output table
```

Optionally specify the EC2 KeyPair name for Zilla Plus via `cdk.context.json`, in the `WebStreaming` `sshKey` variable.

## Deploy the stack via CDK

### Install Project Dependencies

Install the node.js dependencies specified in the `package.json` file:

```bash
npm install
```

### Synthesizing the CloudFormation Template

Run the following command to synthesize your stack into a CloudFormation template:

```bash
cdk synth WebStreaming
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
cdk deploy WebStreaming
```

Sample output:

```bash
Outputs:
WebStreaming.LoadBalancerDnsName = <generated-hostname>.elb.<region>.amazonaws.com
WebStreaming.MqttDnsWildcard = *.your.custom.domain
Stack ARN:
arn:aws:cloudformation:<region>>:<account_id>:stack/WebStreaming/<uuid>
```

### Configure Global DNS

When using a wildcard DNS name for your own domain, such as `*.your.custom.domain` then the DNS entries are setup in your DNS provider for `your.custom.domain`.

Lookup the IP addresses of your load balancer using `nslookup` and the `WebStreaming.LoadBalancerDnsName` stack output.

```bash
nslookup aws-generated-hostname.elb.us-east-1.amazonaws.com
```

For testing purposes you can edit your local /etc/hosts file instead of updating your DNS provider.

For example:

```bash
X.X.X.X  web.example.aklivity.io
```

### Test the Zilla Plus REST and SSE

If you added `web.example.aklivity.io` as the domain, open a terminal and use `curl` to open an SSE connection.

```bash
curl -N --http2 -H "Accept:text/event-stream" -v "https://web.example.aklivity.io:7143/<your path>"
```

Note that `your path` defaults to the mapped Kafka topic in your config.

In another terminal, use `curl` to POST and notice the data arriving on your SSE stream.

```bash
curl -d 'Hello, World' -X POST https://web.example.aklivity.io:7143/<your path>
```
