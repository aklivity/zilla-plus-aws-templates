# Deploy SecurePrivateAccess stack via CDK

This guide will help you gather the necessary AWS values required to configure and deploy Zilla Plus Secure Private Access using CDK that allows Kafka Clients to reach a MSK Serverless cluster from an authorized VPC, even if the client VPC is owned by a different AWS account.

## Prerequisites

1. Deploy [`SecurePrivateAccess`](README.md) stack via CDK
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

9. Verify that your MSK Serverless cluster Security Group allows inbound traffic on port `9098`.

## List the inbound rules for Security Group

```bash
aws ec2 describe-security-groups \
  --group-ids $(aws kafka list-clusters-v2 \
    --cluster-type SERVERLESS \
    --query "ClusterInfoList[?ClusterArn=='<msk-serverless-arn>'].Serverless.VpcConfigs[].SecurityGroupIds[]" \
    --output text) \
  --query "SecurityGroups[].IpPermissions" \
  --output json
```

If the Security Groups do not allow inbound traffic on port `9098`, then make sure to allow that and re-verify.

## Required CDK Context Variables

You can set these `context` variables via `cdk.context.json`, under `SecurePrivateAccess` object.

If your local `cdk.context.json` file does not already exist, copy the example to get started.

```bash
cp cdk.context.example.json cdk.context.json
```

Then, further modify `cdk.context.json` based on the context variable descriptions below.

### `vpcId`: VPC ID

The VPC ID where the MSK Serverless cluster was created.

```bash
aws ec2 describe-subnets \
  --subnet-ids $(aws kafka list-clusters-v2 \
      --cluster-type SERVERLESS \
      --query "ClusterInfoList[?ClusterArn=='<msk-serverless-arn>'].Serverless.VpcConfigs[].SubnetIds[0]" \
      --output text) \
  --query "Subnets[0].VpcId" \
  --output json
```

Set the `VPC ID` for Zilla Plus via `cdk.context.json`, in the `SecurePrivateAccess` `vpcId` variable.

### `msk` related variables

```json
    "msk":
    {
        "servers": "<Bootstrap Servers of your MSK Serverless>",
        "subnetIds": ["<MSK Serverless subnetId1>", "<MSK Serverless subnetId2>"]
    }
```

#### `servers`: MSK Serverless Bootstrap Servers

To get the bootstrap servers of the MSK Serverless Cluster run:

```bash
aws kafka get-bootstrap-brokers \
    --cluster-arn <msk-serverless-arn> \
    --query 'BootstrapBrokerStringSaslIam' \
    --output json
```

Set the `IAM Bootstrap Server` for Zilla Plus via `cdk.context.json`, in the `SecurePrivateAccess` `msk` `servers` variable.

#### `subnetIds`: Subnets of your deployed MSK Serverless Cluster

```bash
aws kafka list-clusters-v2 \
  --cluster-type SERVERLESS \
  --query "ClusterInfoList[?ClusterArn=='<msk-serverless-arn>'].Serverless.VpcConfigs[].SubnetIds[]" \
  --output json
```

Set the Subnet IDs for Zilla Plus via `cdk.context.json`, in the `SecurePrivateAccess` `msk` `subnetIds` variable.

### `private` Zilla Plus variables

```json
    "private":
    {
        "wildcardDNS": "<your private wildcard dns>",
        "certificate": "<your private tls certificate key ARN>",
        "port": "<your private port>"
    }
```

#### `wildcardDNS`: Zilla Plus Wildcard DNS

This variable defines the private wildcard DNS pattern for bootstrap servers to be used by Kafka clients.
It should match the wildcard DNS of the private TLS certificate.

Set the wildcard DNS pattern for Zilla Plus via `cdk.context.json`, in the `SecurePrivateAccess` `private` `wildcardDNS` variable.

#### `certificate`: Zilla Plus TLS Certificate ARN

You need the ARN of either the Certificate Manager certificate or the Secrets Manager secret that contains your TLS certificate private key.

List all certificates in Certificate Manager:

```bash
aws acm list-certificates \
  --certificate-statuses ISSUED \
  --query 'CertificateSummaryList[*].[DomainName,CertificateArn]' \
  --output table
```

Set the AWS Certificate Manager ARN for Zilla Plus via `cdk.context.json`, in the `SecurePrivateAccess` `private` `certificate` variable.

Note: If you specify an AWS Certificate Manager certificate ARN, then Zilla Plus will automatically enable AWS Nitro Enclaves for Zilla Plus and use [ACM for Nitro Enclaves] to install the certificate and seamlessly replace expiring certificates.

List all secrets in Secrets Manager:

```bash
aws secretsmanager list-secrets \
  --query 'SecretList[*].[Name,ARN]' \
  --output table
```

Alternatively, set the AWS Secrets Manager ARN for Zilla Plus via `cdk.context.json`, in the `SecurePrivateAccess` `private` `certificate` variable.

#### `port`: Zilla Plus Port

> Default: `9098`

This variable defines the port number to be used by Kafka clients.

Optionally override the default port for Zilla Plus via `cdk.context.json`, in the `SecurePrivateAccess` `private` `port` variable.

### `capacity`: Zilla Plus EC2 Instances

> Default: `2`

This variable defines the initial number of Zilla Plus instances.

Optionally override the default initial number of instances for Zilla Plus via `cdk.context.json`, in the `SecurePrivateAccess` `private` `capacity` variable.

### `instanceType`: Zilla Plus EC2 Instance Type

> Default: `t3.small` AWS Secrets Manager

> Default: `c6i.xlarge` AWS Certificate Manager (required by [ACM for Nitro Enclaves])

This variable defines the initial number of Zilla Plus instances.

Optionally override the default instance type for Zilla Plus via `cdk.context.json`, in the `SecurePrivateAccess` `private` `instanceType` variable.

### `roleName`: Zilla Plus EC2 Instance Assumed Role

> Default: (generated)

By default the deployment creates the Zilla Plus Role with the necessary roles and policies. If you prefer, you can specify your own role instead.

List all IAM roles:

```bash
aws iam list-roles \
  --query 'Roles[*].[RoleName,Arn]' \
  --output table
```

Optionally override the assumed role (RoleName) for Zilla Plus via `cdk.context.json`, in the `SecurePrivateAccess` `roleName` variable.

### `securityGroups`: Zilla Plus EC2 Instance Security Groups

> Default: (generated)

By default the deployment creates the Zilla Plus Security Group with the necessary ports to be open. If you prefer, you can specify your own security group instead.

List all security groups:

```bash
aws ec2 describe-security-groups \
  --query 'SecurityGroups[*].[GroupId, GroupName]' \
  --output table
```

Optionally override the security group IDs (GroupId) for Zilla Plus via `cdk.context.json`, in the `SecurePrivateAccess` `securityGroups` variable.

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

Optionally specify the CloudWatch Logs Group for Zilla Plus via `cdk.context.json`, in the `SecurePrivateAccess` `cloudwatch` `logs` `group` variable.

#### List All CloudWatch Custom Metric Namespaces

```bash
aws cloudwatch list-metrics \
  --query "Metrics[?\!contains(Namespace, 'AWS')].Namespace" \
  --output table \
| sort \
| uniq
```

Optionally specify the CloudWatch Metrics Namespace for Zilla Plus via `cdk.context.json`, in the `SecurePrivateAccess` `cloudwatch` `metrics` `namespace` variable.

### Enable SSH Access

> Default: (none)

To enable SSH access to the instances you will need the name of an existing EC2 KeyPair.

#### List all EC2 KeyPairs

```bash
aws ec2 describe-key-pairs \
  --query 'KeyPairs[*].[KeyName]' \
  --output table
```

Optionally specify the EC2 KeyPair name for Zilla Plus via `cdk.context.json`, in the `SecurePrivateAccess` `sshKey` variable.

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
cdk deploy SecurePrivateAccess
```

Sample output:

```bash
Outputs:
SecurePrivateAccess.VpcEndpointServiceId = vpce-svc-1234567
SecurePrivateAccess.VpcEndpointServiceName = com.amazonaws.vpce.<region>.vpce-svc-1234567
Stack ARN:
arn:aws:cloudformation:<region>>:<account_id>:stack/SecurePrivateAccess/<uuid>
```

Once your stack is deployed, note the `VPC Endpoint Service Id` and the `VPC Endpoint Service Name`, as you'll need these in the following steps when you add the `VPC Endpoint` from the client VPC.

Deploy the [`SecurePrivateAccessClient`](README.SecurePrivateAccessClient.md) stack to connect to your MSK Serverless cluster from a different VPC.

[ACM for Nitro Enclaves]: https://docs.aws.amazon.com/enclaves/latest/user/nitro-enclave-refapp.html
[Zilla Plus for Amazon MSK]: https://aws.amazon.com/marketplace/pp/prodview-jshnzslazfm44
[Install Node.js]: https://nodejs.org/en/download/package-manager
[Install AWS CDK]: https://docs.aws.amazon.com/cdk/v2/guide/getting_started.html
[Install AWS CLI]: https://docs.aws.amazon.com/cli/latest/userguide/install-cliv2.html
