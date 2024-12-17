# Sample Amazon MSK Deploy via CDK

## Prerequisites

1. [Install Node.js](https://nodejs.org/en/download/package-manager).
2. [Install AWS CLI](https://docs.aws.amazon.com/cli/latest/userguide/install-cliv2.html).
3. Configure AWS CLI and verify your region and credentials: `aws configure list`

    ```text
          Name                    Value             Type    Location
          ----                    -----             ----    --------
       profile                <not set>             None    None
    access_key     ****************XXXX              env
    secret_key     ****************XXXX              env
        region                us-east-1              env    ['AWS_REGION', 'AWS_DEFAULT_REGION']
    ```

4. [Install AWS CDK](https://docs.aws.amazon.com/cdk/v2/guide/getting_started.html#getting_started_install) globally:

    ```bash
    npm install -g aws-cdk
    ```

5. Bootstrap your environment for CDK (required if you’re deploying to a new account/region):

    ```bash
    cdk bootstrap
    ```

## Install and Deploy

1. Install dependencies:

    ```bash
    npm install
    ```

2. Synthesize the CloudFormation template:

    ```bash
    cdk synth
    ```

3. Deploy the stack:

    ```bash
    cdk deploy
    ```

    Confirm the deployment when prompted.

## Clean Up

To destroy the resources created by this stack, run:

```bash
cdk destroy
