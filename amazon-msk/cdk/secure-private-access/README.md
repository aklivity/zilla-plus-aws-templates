# Secure Private Access deploy via CDK

This guide will help you gather the necessary AWS values required to configure and deploy Zilla Plus Secure Private Access using CDK that allows Kafka Clients to reach MSK Serverless inside a different VPC, even if the VPC is in a different region.

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
1. Veirfy that your MSK Serverless Security Group allows inbound traffic on port `9098`. If not make sure to allow that.

### List the inbound rules for MSK Serverless Security Group

```bash
aws ec2 describe-security-groups \
  --group-ids $(aws kafka list-clusters-v2 \
    --cluster-type SERVERLESS \
    --query "ClusterInfoList[?ClusterArn=='<msk-serverless-arn>'].Serverless.VpcConfigs[].SecurityGroupIds[]" \
    --output text) \
  --query "SecurityGroups[].IpPermissions" \
  --output json
```


## Required CDK Context Variables

You can set these variables in your `context` in `cdk.json` file under `zilla-plus` object.

### `vpcId`: VPC ID
The VPC ID where the MSK Serverless lives. 

```bash
aws ec2 describe-subnets --subnet-ids $(aws kafka describe-cluster --cluster-arn <msk-cluster-arn> --query "ClusterInfo.BrokerNodeGroupInfo.ClientSubnets[0]" --output text) --query "Subnets[0].VpcId" --output text
```

### `msk` related variables

```json
    "msk":
    {
        "servers": "<Bootstrap Servers of your MSK Serverless>",
        "subnetIds": "<Subnet IDs of your MSK Serverless>"
    }
```

#### `servers`: MSK Bootstrap Servers and Authentication Method

To get the bootstrap servers of the MSK cluster run:

```bash
aws kafka get-bootstrap-brokers \
    --cluster-arn <msk-serverless-arn> \
    --query '{BootstrapBrokerStringTls: BootstrapBrokerStringTls, BootstrapBrokerStringSaslScram: BootstrapBrokerStringSaslScram, BootstrapBrokerStringSaslIam: BootstrapBrokerStringSaslIam}' \
    --output table
```

Use the `Bootstrap Server` of your desired authentication method to set the `servers` variable.
Set the desired client authentication method based on the MSK cluster setup, using `clientAuthentication` variable. Allowed values are: `SASL/SCRAM`, `mTLS`, `Unauthorized`.


```bash
aws kafka list-clusters-v2 \
  --cluster-type SERVERLESS \
  --query "ClusterInfoList[?ClusterArn=='<msk-serverless-arn>'].Serverless.VpcConfigs[].SubnetIds[]" \
  --output table
```

### `private` Zilla Plus variables

```json
    "private":
    {
        "wildcardDNS": "<your private wildcard dns>",
        "certificate": "<your private tls certificate key ARN>",
        "port": "<your private port>"
    }
```

#### `wildcardDNS`: Private Wildcard DNS

This variable defines the private wildcard DNS pattern for bootstrap servers to be used by Kafka clients.
It should match the wildcard DNS of the private TLS certificate.

#### `certificate`: Private TLS Certificate Key

You need the ARN of either the Certificte Manager certificate or the Secrets Manager secret that contains your TLS certificate private key.

List all certificates in Certificate Manager:

```bash
aws acm list-certificates --certificate-statuses ISSUED --query 'CertificateSummaryList[*].[DomainName,CertificateArn]' --output table
```

Find and note down the ARN of your TLS certificate.

List all secrets in Secrets Manager:

```bash
aws secretsmanager list-secrets --query 'SecretList[*].[Name,ARN]' --output table
```

Find and note down the ARN of the secret that contains your TLS certificate private key.

#### `port`: TCP Port

> Default: `9098`

This variable defines the port number to be used by Kafka clients.


### `capacity`: Zilla Plus Capacity

> Default: `2`

This variable defines the initial number of Zilla Plus instances.

### `instanceType`: Zilla Plus EC2 Instance Type

> Default: `t3.small`

This variable defines the initial number of Zilla Plus instances.

## Optional Features

These features all have default values and can be configured using cdk context variables. If you don't plan to configure any of these features you can skip this section and go to the [Deploy stack using CDK](#deploy-stack-using-cdk) section.

### TLS Certificate via AWS Certificate Manager for Nitro Enclaves

If you want to enable Zilla-plus Nitro Enclaves support all you have to do is provide the `private.certificate` context variable via ACM.

### Custom Zilla Plus Role

By default the deployment creates the Zilla Plus Role with the necessary roles and policies. If you want, you can specify your own role by setting `roleName` context variable in your `cdk.json` under `zilla-plus` object.

List all IAM roles:

```bash
aws iam list-roles --query 'Roles[*].[RoleName,Arn]' --output table
```

Note down the role name `RoleName` of the desired IAM role.

### Custom Zilla Plus Security Groups

By default the deployment creates the Zilla Plus Security Group with the necessary ports to be open. If you want, you can specify your own security group by setting `securityGroups` context variable in your `cdk.json` under `zilla-plus` object.

List all security groups:

```bash
aws ec2 describe-security-groups --query 'SecurityGroups[*].[GroupId, GroupName]' --output table
```

Note down the security group IDs (GroupId) of the desired security groups.

### CloudWatch Integration

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

By default CloudWatch metrics and logging is enabled. To disable CloudWatch logging and metrics, set the `cloudwatch.disabled` context variable to `true`.

You can create or use existing log groups and metric namespaces in CloudWatch.

By default, the deployment creates a CloudWatch Log Groups and Custom Metrics Namespace.
If you want to define your own, follow these steps.

#### List All CloudWatch Log Groups

```bash
aws logs describe-log-groups --query 'logGroups[*].[logGroupName]' --output table
```

This command will return a table listing the names of all the log groups in your CloudWatch.
In your `cdk.json` file add the desired CloudWatch Logs Group for variable name `logs.group` under `zilla-plus` object in the `cloudwatch` variables section.

#### List All CloudWatch Custom Metric Namespaces

```bash
aws cloudwatch list-metrics --query 'Metrics[*].Namespace' --output text | tr '\t' '\n' | sort | uniq | grep -v '^AWS'
```

In your `cdk.json` file add the desired CloudWatch Metrics Namespace for variable name `metrics.namespace` under `zilla-plus` object in the `cloudwatch` variables section.

### Enable SSH Access

To enable SSH access to the instances you will need the name of an existing EC2 KeyPair to set the `sshKey` context variable under `zilla-plus` object.

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

Sample outputs:
```bash
Outputs:
SecurePrivateAccessStack.VpcEndpointServiceId = vpce-svc-1234567
SecurePrivateAccessStack.VpcEndpointServiceName = com.amazonaws.vpce.us-east-1.vpce-svc-1234567
Stack ARN:
arn:aws:cloudformation:us-east-1:<account_id>:stack/SecurePrivateAccessStack/abcd1234
```

Once your stack is deployed, note down the VPC Endpoint Service Id and the VPC Endpoint Service Name, as you'll need this in the following steps when you add the VPC Endpoint from the client VPC.

## Connect to your MSK Serverless from different VPC
### Add a VPC endpoint in the client VPC
You need to add a VPC Endpoint pointing to the Zilla Plus's VPC Endpoint Service in your client VPC. 

```bash
aws ec2 create-vpc-endpoint \
  --vpc-id <Client VPC ID> \
  --service-name <VPC Endpoint Service Name> \
  --subnet-ids <Client Subnets> \
  --vpc-endpoint-type Interface
```

Make sure to save the `VpcEndpointId` and the the first DNS Entry `DNSName`.

### Accept the VPC Endpoint in your VPC Endpoint Service
```bash
aws ec2 accept-vpc-endpoint-connections \
  --service-id <VPC Endpoint Service ID> \
  --vpc-endpoint-ids <VPC Endpoint ID>
```

### Add Route 53 Private Hosted Zone
For your client machine to be able to resolve the custom wilcard DNS configured for Zilla, you need to add a Route 53 Private Hosted Zone, with a `CNAME` record that resolved the custom domain to your previously created VPC Endpoint DNS name.

```bash
aws route53 create-hosted-zone \
  --name example.aklivity.io \
  --vpc VPCRegion=us-east-1,VPCId=vpc-09cb6e2141bdb7b37 \
  --caller-reference <unique caller id> \
  --hosted-zone-config PrivateZone=true 
```

Use the HostedZone.Id in your following command:

```bash
aws route53 change-resource-record-sets \
  --hosted-zone-id /hostedzone/Z0357410VJ4A0M2XZFAK \
  --change-batch '{
    "Changes": [
      {
        "Action": "CREATE",
        "ResourceRecordSet": {
          "Name": "*.us-east-1.example.aklivity.io",
          "Type": "CNAME",
          "TTL": 60,
          "ResourceRecords": [
            {
              "Value": "vpce-0ee315e6fc87716da-ia1ca1zt.vpce-svc-0816be0e665a42f9a.us-east-1.vpce.amazonaws.com"
            }
          ]
        }
      }
    ]
  }'
```


### Launch Client EC2 Instance in different VPC and Install the Kafka Client

Follow the AWS guide to launch an EC2 instance to be able to connect to MSK Serverless.
https://docs.aws.amazon.com/msk/latest/developerguide/create-serverless-cluster-client.html

This documentation mentions that "under VPC, enter the ID of the virtual private cloud (VPC) for your serverless cluster". Now that you deployed Zilla Plus, you can provide the client VPC where you configured the VPC Endpoint. 

Make sure to download one of the latest versions of `aws-msk-iam-auth` jar file if you want to use `OATHBEARER` authentication mechanism, as that's not included in `v1.1.1`

For example:
```bash
wget https://github.com/aws/aws-msk-iam-auth/releases/download/v2.2.0/aws-msk-iam-auth-2.2.0-all.jar
```


### Configure the Kafka Client

With the Kaka client now installed we are ready to configure it and point it at the custom domain configured for Zilla Plus.

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

TODO:
- add iam role readme
- add steps to add more supported regions, point to the filed issue that limits us to automate this


### Test the Kafka Client

This verifies internet connectivity to your MSK Serverless via Zilla Plus.

We can now verify that the Kafka client can successfully communicate with your MSK Serverless from your EC2 instance running in a different VPC to create a topic, then publish and subscribe to the same topic.

If using the wildcard DNS pattern `*.example.aklivity.io`, then we use the following server name for the Kafka client:

```text
boot.example.aklivity.io:9098
```

Replace these bootstrap server names accordingly for your own custom wildcard DNS pattern.

#### Create a Topic

Use the Kafka client to create a topic called zilla-proxy-test, replacing <tls-bootstrap-server-names> in the command below with the TLS proxy names of your Zilla proxy:

```bash
bin/kafka-topics.sh --create --topic zilla-proxy-test --partitions 3 --replication-factor 2 --command-config client.properties --bootstrap-server <tls-bootstrap-server-names>
```
