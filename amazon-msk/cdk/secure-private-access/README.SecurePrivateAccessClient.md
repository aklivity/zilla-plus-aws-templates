# Deploy SecurePrivateAccessClient stack via CDK

This guide will help you gather the necessary AWS values required to configure and deploy Zilla Plus Secure Private Access Client using CDK that allows Kafka Clients to reach a MSK Serverless cluster from an authorized VPC, even if the client VPC is owned by a different AWS account.

## Prerequisites

1. Deploy [`SecurePrivateAccess`](README.md) stack via CDK
2. [Install Node.js].
3. [Install AWS CDK].
4. [Install AWS CLI].
5. Configure AWS CLI: Run `aws configure` and follow the prompts to set up your AWS credentials.
6. Set your aws region: `aws configure set region us-east-1`
7. Verify your region and credentials: `aws configure list`

   ```text
         Name                    Value             Type    Location
         ----                    -----             ----    --------
      profile                <not set>             None    None
   access_key     ****************XXXX              env
   secret_key     ****************XXXX              env
       region                us-east-1              env    ['AWS_REGION', 'AWS_DEFAULT_REGION']
   ```

## Configure the stack

You can set these `context` variables via `cdk.context.json`, under `SecurePrivateAccessClient` object.

If your local `cdk.context.json` file does not already exist, copy the example to get started.

```bash
cp -n cdk.context.example.json cdk.context.json
```

Then, further modify `cdk.context.json` based on the context variable descriptions below.

### `vpcId`: VPC ID

Set the VPC ID where Kafka clients are to be deployed via `cdk.context.json`, in the `SecurePrivateAccessClient` `vpcId` variable.

### `subnetIds`: Subnets of your deployed Kafka clients

Set the Subnet IDs where Kafka clients are to be deployed via `cdk.context.json`, in the `SecurePrivateAccessClient` `subnetIds` variable.

### `server`: Custom domain bootstrap server

This variable defines the bootstrap server to be used by Kafka clients in the format `hostname:port`.

Set the bootstrap server for Kafka clients via `cdk.context.json`, in the `SecurePrivateAccessClient` `server` variable.

### `vpceServiceName` Zilla Plus VPC Endpoint Service Name

> Default: (import `VpcEndpointServiceName` from `SecurePrivateAccess` stack)

Optionally override the default VPC Endpoint Service Name via `cdk.context.json`, in the `SecurePrivateAccessClient`  `vpceServiceName` variable.

## Deploy the stack via CDK

### Install Project Dependencies

Install the node.js dependencies specified in the `package.json` file:

```bash
npm install
```

### Synthesizing the CloudFormation Template

Run the following command to synthesize your stack into a CloudFormation template:

```bash
cdk synth SecurePrivateAccessClient
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
cdk deploy SecurePrivateAccessClient
```

Sample output:

```bash
Outputs:
SecurePrivateAccessClient.VpcEndpointId = vpce-7654321
Stack ARN:
arn:aws:cloudformation:<region>>:<account_id>:stack/SecurePrivateAccessClient/<uuid>
```

Once your stack is deployed, note the `VPC Endpoint ID` as you'll need this to accept the VPC Endpoint connection.

## Accept the VPC Endpoint in your VPC Endpoint Service

```bash
aws ec2 accept-vpc-endpoint-connections \
  --service-id <VPC Endpoint Service ID> \
  --vpc-endpoint-ids <VPC Endpoint ID>
```

The `VPC Endpoint Service ID` can be obtained from the `SecurePrivateAccess` stack outputs.
The `VPC Endpoint ID` can be obtained from the `SecurePrivateAccessClient` stack outputs.

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

#### client.properties for `AWS_MSK_IAM`

```text
security.protocol=SASL_SSL
sasl.mechanism=AWS_MSK_IAM
sasl.jaas.config=software.amazon.msk.auth.iam.IAMLoginModule required;
sasl.client.callback.handler.class=software.amazon.msk.auth.iam.IAMClientCallbackHandler
```

#### client.properties for `OAUTHBEARER`

```text
security.protocol=SASL_SSL
sasl.mechanism=OAUTHBEARER
sasl.jaas.config=org.apache.kafka.common.security.oauthbearer.OAuthBearerLoginModule required;
sasl.login.callback.handler.class=software.amazon.msk.auth.iam.IAMOAuthBearerLoginCallbackHandler
sasl.client.callback.handler.class=software.amazon.msk.auth.iam.IAMOAuthBearerLoginCallbackHandler
```

### Test the Kafka Client

This verifies custom domain connectivity to your MSK Serverless cluster via Zilla Plus, from a different VPC.

We can now verify that the Kafka client successfully communicates with your MSK Serverless cluster from an EC2 instance running in a different VPC to create a topic, then produce and subscribe to the same topic.

If using the wildcard DNS pattern `*.example.aklivity.io`, then use the following server name for the Kafka client:

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

### Destroy the stack

Destroy the `SecurePrivateAccessClient` stack when you no longer need it.

```bash
cdk destroy SecurePrivateAccessClient
```

[Install Node.js]: https://nodejs.org/en/download/package-manager
[Install AWS CDK]: https://docs.aws.amazon.com/cdk/v2/guide/getting_started.html
[Install AWS CLI]: https://docs.aws.amazon.com/cli/latest/userguide/install-cliv2.html
[Create an IAM role for topics on MSK Serverless cluster]: https://docs.aws.amazon.com/msk/latest/developerguide/create-iam-role.html
[Create a client machine to access MSK Serverless cluster]: https://docs.aws.amazon.com/msk/latest/developerguide/create-serverless-cluster-client.html
