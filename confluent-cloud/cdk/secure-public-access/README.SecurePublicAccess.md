# Deploy SecurePublicAccess stack via CDK

This guide will help you gather the necessary AWS and Confluent Cloud values required to configure and deploy Zilla Plus Secure Public Access using CDK that allows Kafka Clients to reach a Confluent Cloud cluster from the Internet. You can use Public, PrivateLink or VPC peering connection type to your Confluent Cloud cluster.

## Prerequisites

1. Subscribe to [Zilla Plus for Confluent Cloud].
2. [Install Node.js].
3. [Install AWS CDK].
4. [Install AWS CLI].
5. [Install Confluent CLI].
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


## Configure the stack

You can set these `context` variables via `cdk.context.json`, under `SecurePublicAccess` object.

If your local `cdk.context.json` file does not already exist, copy the example to get started.

```bash
cp -n examples/cdk.context.SecurePublicAccess.json cdk.context.json
```

Then, further modify `cdk.context.json` based on the context variable descriptions below.

### `internal` related variables

```json
    "internal":
    {
      "servers": "<your Confluent Cloud bootstrap servers>"
    }
```

#### `servers`: Confluent Cloud bootstrap servers

There are three possible ways to connect Zilla Plus to your Confluent Cloud cluster:
1. Public Internet to Confluent Cloud
2. [AWS PrivateLink] to Confluent Cloud 
3. [VPC Peering] to Confluent Cloud

To get the bootstrap servers of the Confluent Cloud Cluster run:

```bash
confluent kafka cluster describe <cluster-id> \
  --output json | jq -r '.endpoint'
```

Set one of the Bootstrap Servers on Zilla Plus via `cdk.context.json`, in the `SecurePublicAccess` `internal` `servers` variable.

### Variables of PrivateLink Connection
Note: skip this if you're not using PrivateLink.

When deploying Zilla Plus to connect through PrivateLink your Confluent Cloud Enterprise cluster will need a network connection. You will need to create a new PrivateLink Attachment in network management tab with the following details:

 - Name: `<network_name>`
 - Add Connection
    - Name: `<privatelink_service_name>`
    - Save the PrivateLink Service Id

#### `internal.privateLinkServiceId` variable

```json
    "internal":
    {
      "privateLinkServiceId": "<your privatelink service id>"
    }
```


### Variables of VPC Peering Connection
Note: skip this if you're not using VPC peering.

When deploying Zilla Plus to connect through VPC Peering, the stack expects that the VPC that Zilla Plus is being deployed to already exists and is configured with VPC Peering in Confluent Cloud. Follow [this guide](https://docs.confluent.io/cloud/current/networking/peering/aws-peering.html) until Step 2, then set the corresponding values for the `vpcId` and `cidrs` stack variables.

#### `vpcId`
The AWS VPC ID you are peering with Confluent Cloud network.

#### `cidrs`
```json
    "cidrs": [
      "10.10.1.0/27",
      "10.10.2.0/27",
      "10.10.3.0/27"
    ],
```
CIDRs of your VPC peering for ALL availability zones.

#### `peeringConnectionId`
```json
    "peeringConnectionId": "pcx-xxxxxxxxxxxxxx"
```

The Peering connections in AWS that was accepted after creating the VPC Peering in Confluent Cloud towards the AWS VPC.


### `external` Zilla Plus variables

```json
    "external":
    {
      "servers": "<your custom domain bootstrap servers>",
      "certificate": "<your custom domain wildcard tls certificate key ARN>"
    }
```

#### `servers`: Custom domain bootstrap servers

This variable defines the external bootstrap server to be used by Kafka clients in the format `hostname:port`.
The external bootstrap server name should match the custom domain wildcard DNS pattern of the external TLS certificate.
The external bootstrap server port should match the internal bootstrap server port.

Set the external bootstrap server for Zilla Plus via `cdk.context.json`, in the `SecurePublicAccess` `external` `servers` variable.

#### `certificate`: Zilla Plus TLS Certificate ARN

You need the ARN of either the Certificate Manager certificate or the Secrets Manager secret that contains your TLS certificate private key.

List all certificates in Certificate Manager:

```bash
aws acm list-certificates \
  --certificate-statuses ISSUED \
  --query 'CertificateSummaryList[*].[DomainName,CertificateArn]' \
  --output table
```

Set the AWS Certificate Manager ARN for Zilla Plus via `cdk.context.json`, in the `SecurePublicAccess` `external` `certificate` variable.

Note: If you specify an AWS Certificate Manager certificate ARN, then Zilla Plus will automatically enable AWS Nitro Enclaves for Zilla Plus and use [ACM for Nitro Enclaves] to install the certificate and seamlessly replace expiring certificates.

List all secrets in Secrets Manager:

```bash
aws secretsmanager list-secrets \
  --query 'SecretList[*].[Name,ARN]' \
  --output table
```

Alternatively, set the AWS Secrets Manager ARN for Zilla Plus via `cdk.context.json`, in the `SecurePublicAccess` `external` `certificate` variable.

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

### `capacity`: Zilla Plus EC2 Instances

> Default: `2`

This variable defines the initial number of Zilla Plus instances.

Optionally override the default initial number of instances for Zilla Plus via `cdk.context.json`, in the `SecurePublicAccess` `capacity` variable.

### `instanceType`: Zilla Plus EC2 Instance Type

> Default: `t3.small` AWS Secrets Manager

> Default: `c6i.xlarge` AWS Certificate Manager (required by [ACM for Nitro Enclaves])

This variable defines the initial number of Zilla Plus instances.

Optionally override the default instance type for Zilla Plus via `cdk.context.json`, in the `SecurePublicAccess` `instanceType` variable.

### `roleName`: Zilla Plus EC2 Instance Assumed Role

> Default: (generated)

By default the deployment creates the Zilla Plus Role with the necessary roles and policies. If you prefer, you can specify your own role instead.

List all IAM roles:

```bash
aws iam list-roles \
  --query 'Roles[*].[RoleName,Arn]' \
  --output table
```

Optionally override the assumed role (RoleName) for Zilla Plus via `cdk.context.json`, in the `SecurePublicAccess` `roleName` variable.

### `securityGroup`: Zilla Plus EC2 Instance Security Group

> Default: (generated)

By default the deployment creates the Zilla Plus Security Group with the necessary ports to be open. If you prefer, you can specify your own security group instead.

List all security groups:

```bash
aws ec2 describe-security-groups \
  --query 'SecurityGroups[*].[GroupId, GroupName]' \
  --output table
```

Optionally override the security group IDs (GroupId) for Zilla Plus via `cdk.context.json`, in the `SecurePublicAccess` `securityGroup` variable.

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

Optionally specify the CloudWatch Logs Group for Zilla Plus via `cdk.context.json`, in the `SecurePublicAccess` `cloudwatch` `logs` `group` variable.

#### List All CloudWatch Custom Metric Namespaces

```bash
aws cloudwatch list-metrics \
  --query "Metrics[?\!contains(Namespace, 'AWS')].Namespace" \
  --output table \
| sort \
| uniq
```

Optionally specify the CloudWatch Metrics Namespace for Zilla Plus via `cdk.context.json`, in the `SecurePublicAccess` `cloudwatch` `metrics` `namespace` variable.

### Enable SSH Access

> Default: (none)

To enable SSH access to the instances you will need the name of an existing EC2 KeyPair.

#### List all EC2 KeyPairs

```bash
aws ec2 describe-key-pairs \
  --query 'KeyPairs[*].[KeyName]' \
  --output table
```

Optionally specify the EC2 KeyPair name for Zilla Plus via `cdk.context.json`, in the `SecurePublicAccess` `sshKey` variable.

## Deploy the stack via CDK

### Install Project Dependencies

Install the node.js dependencies specified in the `package.json` file:

```bash
npm install
```

### Synthesizing the CloudFormation Template

Run the following command to synthesize your stack into a CloudFormation template:

```bash
cdk synth SecurePublicAccess
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
cdk deploy SecurePublicAccess
```

Sample output:

```bash
Outputs:
SecurePublicAccess.CustomDnsWildcard = *.your.custom.domain
SecurePublicAccess.LoadBalancerDnsName = <generated-hostname>.elb.<region>.amazonaws.com
Stack ARN:
arn:aws:cloudformation:<region>>:<account_id>:stack/SecurePublicAccess/<uuid>
```

### Post deployment configuration for PrivateLink
Note: you can skip this step if you're not connecting through PrivateLink.

Copy the `SecurePublicAccess.PrivateLinkVpcEndpointId` output after deploying the stack, and use this to create an Access Point in your PrivateLink Attachment in the network management tab in Confluent Cloud.


#### Configure Global DNS

This ensures that any new Kafka brokers added to the cluster can still be reached via the Zilla proxy. When using a wildcard DNS name for your own domain, such as `*.your.custom.domain` then the DNS entries are setup in your DNS provider for `your.custom.domain`.

Lookup the IP addresses of your load balancer using `nslookup` and the `SecurePublicAccess.LoadBalancerDnsName` stack output.

```bash
nslookup aws-generated-hostname.elb.us-east-1.amazonaws.com
```

For testing purposes you can use `dnsmasq` to create wildcard DNS instead of updating your DNS provider.

Use `brew` to install `dnsmasq`

```bash
brew install dnsmasq
```

Append a new entry to your `dnsmasq` configuration file. Change the IP and domain according to your output and wildcard DNS domain.
```bash
echo 'address=/example.aklivity.io/<your NLB IP address>' >> $(brew --prefix)/etc/dnsmasq.conf
```

Start the service (or restart if it's already running):
```bash
sudo brew services start dnsmasq
```

Create a new resolver for `example.aklivity.io` domain:
```bash
sudo mkdir -p /etc/resolver
sudo vi /etc/resolver/example.aklivity.io
```

Add the following line to resolve DNS for `example.aklivity.io` using `dnsmasq`:
```properties
nameserver 127.0.0.1
```

In the example above, we setup our local environment so that all `*.example.aklivity.io` DNS will resolve to the IP address of our newly created NLB.

Now you can use any Kafka client to connect to your Confluent Cloud cluster via your custom domain, using Kafka bootstrap server  or `bootstrap.your.custom.domain:9092` and SASL PLAIN authentication using you Confluent Cloud API key.


### Destroy the stack

Destroy the `SecurePublicAccess` stack when you no longer need it.

```bash
cdk destroy SecurePublicAccess
```

[ACM for Nitro Enclaves]: https://docs.aws.amazon.com/enclaves/latest/user/nitro-enclave-refapp.html
[Zilla Plus for Confluent Cloud]: https://aws.amazon.com/marketplace/pp/prodview-eblxkinsqbaks
[Install Node.js]: https://nodejs.org/en/download/package-manager
[Install AWS CDK]: https://docs.aws.amazon.com/cdk/v2/guide/getting_started.html
[Install AWS CLI]: https://docs.aws.amazon.com/cli/latest/userguide/install-cliv2.html
[Install Confluent CLI]: https://docs.confluent.io/confluent-cli/current/install.html
[AWS PrivateLink]: https://docs.confluent.io/cloud/current/networking/private-links/aws-privatelink.html
[VPC Peering]: https://docs.confluent.io/cloud/current/networking/peering/aws-peering.html
