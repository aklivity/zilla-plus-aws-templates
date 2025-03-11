# Deploy MskServerlessCluster stack via CDK

This guide will help you gather the necessary AWS values required to configure and deploy Zilla Plus MSK Serverless Cluster using CDK.

## Prerequisites

1. [Install Node.js].
2. [Install AWS CDK].
3. [Install AWS CLI].
4. Configure AWS CLI: Run `aws configure` and follow the prompts to set up your AWS credentials.
5. Set your aws region: `aws configure set region us-east-1`
6. Verify your region and credentials: `aws configure list`

   ```text
         Name                    Value             Type    Location
         ----                    -----             ----    --------
      profile                <not set>             None    None
   access_key     ****************XXXX              env
   secret_key     ****************XXXX              env
       region                us-east-1              env    ['AWS_REGION', 'AWS_DEFAULT_REGION']
   ```

## Configure the stack

You can set these `context` variables via `cdk.context.json`, under `MskServerlessCluster` object.

If your local `cdk.context.json` file does not already exist, copy the example to get started.

```bash
cp -n examples/cdk.context.MskServerlessCluster.json cdk.context.json
```

Otherwise copy the `MskServerlessCluster` object into your existing `cdk.context.json` file.

Then, further modify `cdk.context.json` based on the context variable descriptions below.

### `vpc`: VPC ID

```json
    "vpc":
    {
      "cidr": "10.0.0.0/16"
    }
```

Set the VPC CIDR for your MSK Serverless cluster via `cdk.context.json`, in the `MskServerlessCluster` `vpc` variable.

### `subnets`: Subnets of your deployed Kafka clients

```json
    "subnets": {
      "private": {
        "cidrMask": 24
      },
      "public": {
        "cidrMask": 24
      }
    }
```

Set the public and private subnet CIDR masks for your MSK Serveless cluster via `cdk.context.json`, in the `MskServerlessCluster` `subnets` variable.

## Deploy the stack via CDK

### Install Project Dependencies

Install the node.js dependencies specified in the `package.json` file:

```bash
npm install
```

### Synthesizing the CloudFormation Template

Run the following command to synthesize your stack into a CloudFormation template:

```bash
cdk synth MskServerlessCluster
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
cdk deploy MskServerlessCluster
```

Sample output:

```bash
Outputs:
MskServerlessCluster.ClusterArn = arn:aws:kafka:<region>:<account_id>:cluster/zilla-plus-MskServerlessCluster/<uuid>
MskServerlessCluster.RoleArn = arn:aws:<region>:<account_id>:role/zilla-plus-MskServerlessCluster
MskServerlessCluster.SubnetIds = ["subnet-id1","subnet-id2"]
MskServerlessCluster.VpcId = vpc-0123456789abcdef1
Stack ARN:
arn:aws:cloudformation:<region>:<account_id>:stack/MskServerlessCluster/<uuid>
```

Once your stack is deployed, note the `VpcId` as you'll need this to deploy the [`SecurePrivateAccess`](README.SecurePrivateAccess.md) stack, and the `RoleArn` as you'll need that to test the [`SecurePrivateAccessClient`](README.SecurePrivateAccessClient.md) stack.

### Destroy the stack

Destroy the `MskServerlessCluster` stack when you no longer need it.

```bash
cdk destroy MskServerlessCluster
```

[Install Node.js]: https://nodejs.org/en/download/package-manager
[Install AWS CDK]: https://docs.aws.amazon.com/cdk/v2/guide/getting_started.html
[Install AWS CLI]: https://docs.aws.amazon.com/cli/latest/userguide/install-cliv2.html
