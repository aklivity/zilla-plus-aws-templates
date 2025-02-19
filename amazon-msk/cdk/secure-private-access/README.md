# Secure Private Access deploy via CDK

This guide will help you gather the necessary AWS values required to configure and deploy Zilla Plus Secure Private Access using CDK that allows Kafka Clients to reach a MSK Serverless cluster from an authorized VPC, even if the client VPC is owned by a different AWS account.

## Prerequisites

1. Subscribe to [Zilla Plus for Amazon MSK].
1. [Install Node.js].
1. [Install AWS CDK].
1. [Install AWS CLI].
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
1. Verify that your MSK Serverless cluster Security Group allows inbound traffic on port `9098`.

#### List the inbound rules for Security Group

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

You can set these `context` variables via `cdk.context.json`, under `zilla-plus` object.

First, copy the example to `cdk.context.json`.
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

Set the `IAM Bootstrap Server` for Zilla Plus via `cdk.context.json`, in the `zilla-plus` `msk` `servers` variable.

#### `subnetIds`: Subnets of your deployed MSK Serverless Cluster

```bash
aws kafka list-clusters-v2 \
  --cluster-type SERVERLESS \
  --query "ClusterInfoList[?ClusterArn=='<msk-serverless-arn>'].Serverless.VpcConfigs[].SubnetIds[]" \
  --output json
```

Set the Subnet IDs for Zilla Plus via `cdk.context.json`, in the `zilla-plus` `msk` `subnetIds` variable.


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

Set the wildcard DNS pattern for Zilla Plus via `cdk.context.json`, in the `zilla-plus` `private` `wildcardDNS` variable.


#### `certificate`: Zilla Plus TLS Certificate ARN

You need the ARN of either the Certificte Manager certificate or the Secrets Manager secret that contains your TLS certificate private key.

List all certificates in Certificate Manager:

```bash
aws acm list-certificates \
  --certificate-statuses ISSUED \
  --query 'CertificateSummaryList[*].[DomainName,CertificateArn]' \
  --output table
```

Set the AWS Certificate Manager ARN for Zilla Plus via `cdk.context.json`, in the `zilla-plus` `private` `certificate` variable.

Note: If you specify an AWS Certificate Manager certificate ARN, then Zilla Plus will automatically enable AWS Nitro Enclaves for Zilla Plus and use [ACM for Nitro Enclaves] to install the certificate and seamlessly replace expiring certificates.


List all secrets in Secrets Manager:

```bash
aws secretsmanager list-secrets \
  --query 'SecretList[*].[Name,ARN]' \
  --output table
```

Alternatively, set the AWS Secrets Manager ARN for Zilla Plus via `cdk.context.json`, in the `zilla-plus` `private` `certificate` variable.

#### `port`: Zilla Plus Port

> Default: `9098`

This variable defines the port number to be used by Kafka clients.

Optionally override the default port for Zilla Plus via `cdk.context.json`, in the `zilla-plus` `private` `port` variable.


### `capacity`: Zilla Plus EC2 Instances

> Default: `2`

This variable defines the initial number of Zilla Plus instances.

Optionally override the default initial number of instances for Zilla Plus via `cdk.context.json`, in the `zilla-plus` `private` `capacity` variable.


### `instanceType`: Zilla Plus EC2 Instance Type

> Default: `t3.small` AWS Secrets Manager

> Default: `c6i.xlarge` AWS Certificate Manager (required by [ACM for Nitro Enclaves])

This variable defines the initial number of Zilla Plus instances.

Optionally override the default instance type for Zilla Plus via `cdk.context.json`, in the `zilla-plus` `private` `instanceType` variable.


### `roleName`: Zilla Plus EC2 Instance Assumed Role

> Default: (generated)

By default the deployment creates the Zilla Plus Role with the necessary roles and policies. If you prefer, you can specify your own role instead.

List all IAM roles:

```bash
aws iam list-roles \
  --query 'Roles[*].[RoleName,Arn]' \
  --output table
```

Optionally override the assumed role (RoleName) for Zilla Plus via `cdk.context.json`, in the `zilla-plus` `roleName` variable.


### `securityGroups`: Zilla Plus EC2 Instance Security Groups

> Default: (generated)

By default the deployment creates the Zilla Plus Security Group with the necessary ports to be open. If you prefer, you can specify your own security group instead.

List all security groups:

```bash
aws ec2 describe-security-groups \
  --query 'SecurityGroups[*].[GroupId, GroupName]' \
  --output table
```

Optionally override the security group IDs (GroupId) for Zilla Plus via `cdk.context.json`, in the `zilla-plus` `securityGroups` variable.


### `cloudwatch` Zilla Plus variables

> Default: (generated)

```json
    "cloudwatch":
    {
        "disabled": false,
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

By default CloudWatch metrics and logging is enabled.

Optionally disable CloudWatch logging and metrics for Zilla Plus via `cdk.context.json`, by setting the `zilla-plus` `cloudwatch` `disabled` variable to `true`.

You can create or use existing log groups and metric namespaces in CloudWatch.

By default, the deployment creates a CloudWatch Log Groups and Custom Metrics Namespace.

If you prefer to define your own, follow these steps.

#### List All CloudWatch Log Groups

```bash
aws logs describe-log-groups \
  --query 'logGroups[*].[logGroupName]' \
  --output table
```

This command returns a table listing the names of all the log groups in your CloudWatch in the current AWS region.

Optionally override the CloudWatch Logs Group for Zilla Plus via `cdk.context.json`, in the `zilla-plus` `cloudwatch` `logs` `group` variable.

#### List All CloudWatch Custom Metric Namespaces

```bash
aws cloudwatch list-metrics \
  --query "Metrics[?\!contains(Namespace, 'AWS')].Namespace" \
  --output table \
| sort \
| uniq 
```

Optionally override the CloudWatch Metrics Namespace for Zilla Plus via `cdk.context.json`, in the `zilla-plus` `cloudwatch` `metrics` `namespace` variable.


### Enable SSH Access

> Default: (none)

To enable SSH access to the instances you will need the name of an existing EC2 KeyPair.

List all EC2 KeyPairs:

```bash
aws ec2 describe-key-pairs \
  --query 'KeyPairs[*].[KeyName]' \
  --output table
```

Optionally specify the KeyPair name for Zilla Plus via `cdk.context.json`, in the `zilla-plus` `sshKey` variable.

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

Sample output:
```bash
Outputs:
SecurePrivateAccessStack.VpcEndpointServiceId = vpce-svc-1234567
SecurePrivateAccessStack.VpcEndpointServiceName = com.amazonaws.vpce.<region>.vpce-svc-1234567
Stack ARN:
arn:aws:cloudformation:<region>>:<account_id>:stack/SecurePrivateAccessStack/abcd1234
```

Once your stack is deployed, note the `VPC Endpoint Service Id` and the `VPC Endpoint Service Name`, as you'll need these in the following steps when you add the `VPC Endpoint` from the client VPC.

## Connect to your MSK Serverless from a different VPC

### Add a VPC endpoint in the client VPC

You need to add a VPC Endpoint pointing to the Zilla Plus's VPC Endpoint Service in your client VPC. 

```bash
aws ec2 create-vpc-endpoint \
  --vpc-id <Client VPC ID> \
  --service-name <VPC Endpoint Service Name> \
  --subnet-ids <Client Subnets> \
  --vpc-endpoint-type Interface
```

The `create-vpc-endpoint` response returns the newly created `VpcEndpointId` which is needed for the remaining steps.

### Accept the VPC Endpoint in your VPC Endpoint Service

```bash
aws ec2 accept-vpc-endpoint-connections \
  --service-id <VPC Endpoint Service ID> \
  --vpc-endpoint-ids <VPC Endpoint ID>
```

### Add Route 53 Private Hosted Zone

For your client machine to be able to resolve the custom wilcard DNS configured for Zilla Plus, you need to add a Route 53 Private Hosted Zone, with an `ALIAS` record that resolves the wildcard custom domain to the client VPC Endpoint DNS name.

First, create an empty Private Hosted Zone.

Note: Change the `Name` of the hosted zone according to your custom domain.
```bash
aws route53 create-hosted-zone \
  --name example.aklivity.io \
  --vpc VPCRegion=<region>,VPCId=<Your Client VPC ID> \
  --caller-reference <unique caller id> \
  --hosted-zone-config PrivateZone=true 
```
The `create-hosted-zone` response includes the newly created custom domain `HostedZone` `Id` in `Z##########` format, which is needed to create DNS records within the hosted zone.

Lookup the `VPC Endpoint` `HostedZoneId` and `DnsName` so we can create the `ALIAS` record.
```
aws ec2 describe-vpc-endpoints \
  --vpc-endpoint-ids <Your Client VPC Endpoint ID> \
  --query "VpcEndpoints[*].[VpcEndpointId,DnsEntries]"
```

Create the wildcard custom domain DNS record in the Private Hosted Zone.
 - use the custom domain `HostedZone` `Id` from `create-hosted-zone` above
 - use the `VPC Endpoint` first entry `DnsName` and `HostedZoneId` from `describe-vpc-endpoints` above

Note: Change the `Name` of the record according to your custom domain.

```bash
aws route53 change-resource-record-sets \
  --hosted-zone-id <Your Custom Domain Private Hosted Zone ID> \
  --change-batch '{
    "Changes": [
      {
        "Action": "CREATE",
        "ResourceRecordSet": {
          "Name": "*.example.aklivity.io",
          "Type": "A",
          "AliasTarget": {
            "HostedZoneId": "VPC Endpoint Hosted Zone Id of the DNS",
            "DNSName": "VPC Endpoint DNS Name",
            "EvaluateTargetHealth": false
          }
        }
      }
    ]
  }'
```


### Create IAM Role for MSK Serverless

Follow the AWS guide to [Create an IAM role for topics on MSK Serverless cluster] to grants access to certain Kafka operations.

You can use the created role in the next step for client machine that assumes this role and uses it.

### Launch Client EC2 Instance in different VPC and Install the Kafka Client

Follow the AWS guide to [Create a client machine to access MSK Serverless cluster] to be able to connect from your Kafka client running in a different VPC.

This documentation mentions that "under VPC, enter the ID of the virtual private cloud (VPC) for your serverless cluster". Now that you deployed Zilla Plus, you can provide the client VPC where you configured the VPC Endpoint instead. 

Make sure to download one of the latest versions of `aws-msk-iam-auth` jar file if you want to use `OAUTHBEARER` authentication mechanism, as that's not included in `v1.1.1`

For example:
```bash
wget https://github.com/aws/aws-msk-iam-auth/releases/download/v2.2.0/aws-msk-iam-auth-2.2.0-all.jar
```


### Configure the Kafka Client

With the Kafka client now installed, we are ready to configure IAM authorization.

You can either choose to use `AWS_MSK_IAM` or `OAUTHBEARER`.

##### client.properties for `AWS_MSK_IAM`

```text
security.protocol=SASL_SSL
sasl.mechanism=AWS_MSK_IAM
sasl.jaas.config=software.amazon.msk.auth.iam.IAMLoginModule required;
sasl.client.callback.handler.class=software.amazon.msk.auth.iam.IAMClientCallbackHandler
```

##### client.properties for `OAUTHBEARER`

```text
security.protocol=SASL_SSL
sasl.mechanism=OAUTHBEARER
sasl.jaas.config=org.apache.kafka.common.security.oauthbearer.OAuthBearerLoginModule required;
sasl.login.callback.handler.class=software.amazon.msk.auth.iam.IAMOAuthBearerLoginCallbackHandler
sasl.client.callback.handler.class=software.amazon.msk.auth.iam.IAMOAuthBearerLoginCallbackHandler
```

### Test the Kafka Client

This verifies custom domain connectivity to your MSK Serverless cluster via Zilla Plus, from a different VPC.

We can now verify that the Kafka client can successfully communicate with your MSK Serverless cluster from an EC2 instance running in a different VPC to create a topic, then produce and subscribe to the same topic.

If using the wildcard DNS pattern `*.example.aklivity.io`, then we use the following server name for the Kafka client:

```text
boot.example.aklivity.io:9098
```

Note: Replace these bootstrap server names accordingly for your own custom wildcard DNS pattern.

#### Create a Topic

Use the Kafka client to create a topic called `zilla-plus-test`, updating `boot.example.aklivity.io:9098` in the command below to use your Zilla Plus custom domain:

```bash
bin/kafka-topics.sh --create \
    --topic zilla-plus-test \
    --partitions 3 \
    --replication-factor 2 \
    --command-config client.properties \
    --bootstrap-server boot.example.aklivity.io:9098
```

Now you can produce and subscribe to the `zilla-plus-test` topic in your MSK Serverless cluster from your client VPC.

### Reaching MSK Serverless from a different region

Although same region connectivity is naturally considered best practice, Zilla Plus does not prevent you from reaching an MSK Serverless cluster across regions if needed. First add the desired client region to the `Supported regions` section of the `VPC Endpoint Service` created during deployment of this Zilla Plus stack.

Then on the client EC2 instance in a different region, follow the `Connect to your MSK Serverless from a different VPC` steps above to create the cross-region `VPC Endpoint` and set the target region so the AWS IAM login module used by your Kafka client can authenticate properly to the MSK Serverless cluster via Zilla Plus.
```bash
export AWS_REGION=<target region>
```

[ACM for Nitro Enclaves]: https://docs.aws.amazon.com/enclaves/latest/user/nitro-enclave-refapp.html
[Zilla Plus for Amazon MSK]: https://aws.amazon.com/marketplace/pp/prodview-jshnzslazfm44
[Install Node.js]: https://nodejs.org/en/download/package-manager
[Install AWS CDK]: https://docs.aws.amazon.com/cdk/v2/guide/getting_started.html
[Install AWS CLI]: https://docs.aws.amazon.com/cli/latest/userguide/install-cliv2.html
[Create an IAM role for topics on MSK Serverless cluster]: https://docs.aws.amazon.com/msk/latest/developerguide/create-iam-role.html
[Create a client machine to access MSK Serverless cluster]: https://docs.aws.amazon.com/msk/latest/developerguide/create-serverless-cluster-client.html
