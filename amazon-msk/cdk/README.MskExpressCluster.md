# Deploy MskExpressCluster stack via CDK

This guide will help you gather the necessary AWS values required to configure and deploy an MSK Express cluster in its own VPC.

## Prerequisites

1. [Install Node.js].
2. [Install AWS CLI].
3. [Install AWS CDK].
4. Configure AWS CLI: Run `aws configure` and follow the prompts to set up your AWS credentials.
5. Set your aws region: `aws configure set region us-east-1`
6. Configure AWS CLI and verify your region and credentials: `aws configure list`

    ```text
          Name                    Value             Type    Location
          ----                    -----             ----    --------
       profile                <not set>             None    None
    access_key     ****************XXXX              env
    secret_key     ****************XXXX              env
        region                us-east-1              env    ['AWS_REGION', 'AWS_DEFAULT_REGION']
    ```

7. Bootstrap your environment for CDK (required if you’re deploying to a new account/region):

    ```bash
    cdk bootstrap
    ```

## Configure the stack

You can set these `context` variables via `cdk.context.json`, under `MskExpressCluster` object.

If your local `cdk.context.json` file does not already exist, copy the example to get started.

```bash
cp -n examples/cdk.context.MskExpressCluster.json cdk.context.json
```

Then, further modify `cdk.context.json` based on the context variable descriptions below.

### `vpc`

```json
  "vpc": {
    "cidr": "10.0.0.0/16"
  }
```

#### `cidr`

Optionally specify the VPC CIDR block for the MSK cluster via `cdk.context.json`, in the `MskExpressCluster` `vpc` `cidr` variable.

### `subnets`

```json
  "subnets": {
    "cidrMask": 24
  }
```

#### `cidrMask`

Optionally specify the Subnet CIDR mask for the MSK cluster via `cdk.context.json`, in the `MskExpressCluster` `subnets` `cidrMask` variable.

### `authentication`: MSK Client Authentication

```json
  "authentication": {
    "unauthenticated": false,
    "sasl": {
      "iam": false,
      "scram": "alice"
    },
    "mtls": [ "<your Amazon MSK Express Certificate Authority ARN>" ]
  }
```

#### `unauthenticated`

Optionally enable unauthenticated access to the MSK cluster via `cdk.context.json`, in the `MskExpressCluster` `authentication` `unauthenticated` variable.

#### `sasl`

Optionally enable IAM access to the MSK cluster via `cdk.context.json`, in the `MskExpressCluster` `authentication` `sasl` `iam` variable.

The `scram` variable contains the username for accessing the MSK cluster via SASL/SCRAM.

Optionally enable SCRAM access to the MSK cluster via `cdk.context.json`, in the `MskExpressCluster` `authentication` `sasl` `scram` variable.

#### `mtls`

The `tls` variable contains an array of Certificate Authority ARNs used to authenticate TLS client certificates.

Optionally enable mutual TLS access to the MSK cluster via `cdk.context.json`, in the `MskExpressCluster` `authentication` `mtls` variable.

### Deploy the stack

Deploy your resources to AWS:

```bash
cdk deploy MskExpressCluster
```

Sample output:

```bash
Outputs:
MskExpressCluster.MskClusterArn = arn:aws:kafka:<region>:<account_id>:cluster/zilla-plus-MskExpressCluster/<uuid>
Stack ARN:
arn:aws:cloudformation:<region>:<account_id>:stack/MskExpressCluster/<uuid>
```

### Destroy the stack

To destroy the resources created by this stack, run:

```bash
cdk destroy MskExpressCluster
```

## Notes

The `MskExpressCluster` stack deploys an MSK Express cluster with these defaults:

- Kafka version `3.6.0`
- Broker instance type `express.m7g.large`
- `3` broker nodes across isolated subnets

[Install Node.js]: https://nodejs.org/
[Install AWS CLI]: https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html
[Install AWS CDK]: https://docs.aws.amazon.com/cdk/v2/guide/getting_started.html
