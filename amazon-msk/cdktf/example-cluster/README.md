# Sample Amazon MSK deploy via CDKTF

## Prerequisites

1. [Install Node.js](https://nodejs.org/en/download/package-manager).
1. [Install CDKTF](https://developer.hashicorp.com/terraform/tutorials/cdktf/cdktf-install).
1. [Install AWS CLI](https://docs.aws.amazon.com/cli/latest/userguide/install-cliv2.html).
1. Configure AWS CLI and Verify your region and credentials: `aws configure list`

    ```text
          Name                    Value             Type    Location
          ----                    -----             ----    --------
       profile                <not set>             None    None
    access_key     ****************XXXX              env
    secret_key     ****************XXXX              env
        region                us-east-1              env    ['AWS_REGION', 'AWS_DEFAULT_REGION']
    ```

## Install and deploy

```bash
npm install
```

```bash
cdktf deploy
```
