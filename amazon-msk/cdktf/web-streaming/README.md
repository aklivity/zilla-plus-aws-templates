# Web Streaming Terraform deploy via CDKTF

This guide will help you gather the necessary AWS values required to configure and deploy Zilla Plus Web Streaming using CDKTF.

## Prerequisites

1. Be subscribed to [Zilla Plus for Amazon MSK](https://aws.amazon.com/marketplace/pp/prodview-jshnzslazfm44).
1. [Install Node.js](https://nodejs.org/en/download/package-manager).
1. [Install Terraform](https://developer.hashicorp.com/terraform/tutorials/aws-get-started/install-cli).
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

## (optional) Create an example MSK cluster

If you don't have an existing MSK cluster you can use our example MSK deployment with basic configuration and SASL/SCRAM access. Follow the instructions inside the [example-cluster](../example-cluster/README.md) folder to deploy the example MSK cluster. Note the `mskClusterName` from the outputs as you'll need this later.

## Required CDKTF Context Variables

You can set these variables in your `context` in `cdktf.json` file under `zilla-plus` object.

### `msk` related variables

```json
    "msk":
    {
      "cluster": "<your MSK cluster name>",
      "credentials": "<Secret Name associated with your MSK cluster>"  
    },
```

#### `cluster`: MSK Cluster Name

To get a list all MSK clusters run:

```bash
aws kafka list-clusters --query 'ClusterInfoList[*].[ClusterName,ClusterArn]' --output table
```

Use the `ClusterName` of your desired MSK cluster for this variable.

#### `credentials`: MSK Credentials Secret Name

Provide the Secret Name that is associated with your MSK cluster. If you use our provided example cluster, there is already a secret associated with the cluster called `AmazonMSK_alice`.

List all secrets ub Secrets Manager that can be associated with MSK:

```bash
aws secretsmanager list-secrets --query "SecretList[?starts_with(Name, 'AmazonMSK_')].Name" --output table
```

### `mappings`: Kafka Topic Mappings

```json
    "mappings": 
    [
        {"topic": "<your kafka topic>"},
        {"topic": "<your kafka topic>", "path": "<your custom path>"}
    ]
```

This array variable defines the Kafka topics exposed through REST and SSE. If `path` is not specified, the topic will be exposed on `/<path>`
To enable a custom path for the Kafka topic, set the `path` field to the path where the Kafka topic should be exposed.

### `public` Zilla Plus variables

```json
    "public":
    {
        "certificate": "<your public tls certificate key ARN>",
        "port": "<your public port>"
    }
```

#### `certificate`: Public TLS Certificate Key

You need the ARN of the Secrets Manager secret that contains your public TLS certificate private key.

List all secrets in Secrets Manager:

```bash
aws secretsmanager list-secrets --query 'SecretList[*].[Name,ARN]' --output table
```

Find and note down the ARN of the secret that contains your public TLS certificate private key.


#### `port`: Public TCP Port

> Default: `7143`

This variable defines the public port number to be used by REST and SSE clients.


### `capacity`: Zilla Plus Capacity

> Default: `2`

This variable defines the initial number of Zilla Plus instances.

### `instanceType`: Zilla Plus EC2 Instance Type

> Default: `t3.small`

This variable defines the initial number of Zilla Plus instances.

## Optional Features

These features all have default values and can be configured using cdk context variables. If you don't plan to configure any of these features you can skip this section and go to the [Deploy stack using Terraform](#deploy-stack-using-terraform) section.

### Internet Gateway ID

If you already have an Internet Gateway in the MSK's VPN it should be provided via the `igwId` context variable in your `cdktf.json` under `zilla-plus` object. If not set the deployment will attempt to create on in the VPC.

To query the IGW_ID of your MSK's VPN use the following comman:
```bash
SUBNET_ID=$(aws kafka describe-cluster --cluster-arn <you-msk-arn> --query "ClusterInfo.BrokerNodeGroupInfo.ClientSubnets[0]" --output text)
VPC_ID=$(aws ec2 describe-subnets --subnet-ids $SUBNET_ID --query "Subnets[0].VpcId" --output text)
aws ec2 describe-internet-gateways --filters "Name=attachment.vpc-id,Values=$VPC_ID" --query "InternetGateways[0].InternetGatewayId" --output text
```

### Custom Zilla Plus Role

By default the deployment creates the Zilla Plus Role with the necessary roles and policies. If you want, you can specify your own role by setting `roleName` context variable in your `cdktf.json` under `zilla-plus` object.

List all IAM roles:

```bash
aws iam list-roles --query 'Roles[*].[RoleName,Arn]' --output table
```

Note down the role name `RoleName` of the desired IAM role.

### Custom Zilla Plus Security Groups

By default the deployment creates the Zilla Plus Security Group with the necessary ports to be open. If you want, you can specify your own security group by setting `securityGroups` context variable in your `cdktf.json`.

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
In your `cdktf.json` file add the desired CloudWatch Logs Group for variable name `logs.group` under `zilla-plus` object in the `cloudwatch` variables section.


#### List All CloudWatch Custom Metric Namespaces

```bash
aws cloudwatch list-metrics --query 'Metrics[*].Namespace' --output text | tr '\t' '\n' | sort | uniq | grep -v '^AWS'
```

In your `cdktf.json` file add the desired CloudWatch Metrics Namespace for variable name `metrics.namespace` under `zilla-plus` object in the `cloudwatch` variables section.

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

To enable the Glue Schema Registry for schema fetching, set the context variable `glueRegistry` to the name of the Glue Registry.

1. List all Glue Registries:

```bash
aws glue list-registries --query 'Registries[*].[RegistryName]' --output table
```

Note down the Glue Registry name (RegistryName) you want to use.

### Enable SSH Access

To enable SSH access to the instances you will need the name of an existing EC2 KeyPair to set the `sshKey` context variable.

List all EC2 KeyPairs:

```bash
aws ec2 describe-key-pairs --query 'KeyPairs[*].[KeyName]' --output table
```

Note down the KeyPair name `KeyName` you want to use.

## Deploy stack using Terraform

### Install Project Dependencies

Install the node.js dependencies specified in the `package.json` file:

```bash
npm install
```

### Synthesize the Terraform Configuration

First, you need to synthesize the Terraform configuration from the CDKTF code.

Navigate to the CDKTF project directory.

Run the following command to synthesize the configuration:

```bash
npm run synth
```

This command will generate the necessary Terraform JSON configuration files in the cdktf.out directory.

### Run terraform init and apply

After synthesizing the configuration you can use `terraform` to deploy zilla.

Initialize terraform.

```bash
terraform -chdir=cdktf.out/stacks/web-streaming init
```

Apply the plan, review the resources to be create, and confirm to deploy the resources:

```bash
terraform -chdir=cdktf.out/stacks/web-streaming apply -auto-approve
```

```bash
...
Changes to Outputs:
  + NetworkLoadBalancerOutput = (known after apply)
aws_internet_gateway.InternetGateway: Creating...
aws_cloudwatch_log_group.loggroup: Creating...
aws_route_table.PublicRouteTable: Creating...
aws_subnet.PublicSubnet2: Creating...
aws_iam_role.zilla_plus_role: Creating...
aws_subnet.PublicSubnet1: Creating...
aws_lb_target_group.NLBTargetGroup: Creating...
aws_security_group.ZillaPlusSecurityGroup: Creating...
aws_cloudwatch_log_group.loggroup: Creation complete after 1s [id=web-streaming-group]
aws_internet_gateway.InternetGateway: Creation complete after 1s [id=igw-XXXX]
aws_route_table.PublicRouteTable: Creation complete after 2s [id=rtb-XXXX]
aws_route.PublicRoute: Creating...
aws_iam_role.zilla_plus_role: Creation complete after 2s [id=zilla_plus_role]
aws_iam_role_policy.ZillaPlusRolePolicy: Creating...
aws_iam_instance_profile.zilla_plus_instance_profile: Creating...
aws_route.PublicRoute: Creation complete after 1s [id=r-rtb-XXXX]
aws_lb_target_group.NLBTargetGroup: Creation complete after 3s [id=arn:aws:elasticloadbalancing:<region>:XXXX:targetgroup/nlb-target-group/XXXX]
aws_iam_role_policy.ZillaPlusRolePolicy: Creation complete after 1s [id=zilla_plus_role:terraform-XXXX]
aws_iam_instance_profile.zilla_plus_instance_profile: Creation complete after 1s [id=zilla_plus_role]
aws_security_group.ZillaPlusSecurityGroup: Creation complete after 4s [id=sg-XXXX]
aws_launch_template.ZillaPlusLaunchTemplate: Creating...
aws_launch_template.ZillaPlusLaunchTemplate: Creation complete after 1s [id=lt-XXXX]
aws_subnet.PublicSubnet2: Still creating... [10s elapsed]
aws_subnet.PublicSubnet1: Still creating... [10s elapsed]
aws_subnet.PublicSubnet1: Creation complete after 12s [id=subnet-XXXX]
aws_subnet.PublicSubnet2: Creation complete after 12s [id=subnet-XXXX]
aws_route_table_association.PublicSubnet1RouteTableAssociation: Creating...
aws_route_table_association.PublicSubnet2RouteTableAssociation: Creating...
aws_lb.NetworkLoadBalancer: Creating...
aws_autoscaling_group.ZillaPlusGroup: Creating...
aws_route_table_association.PublicSubnet1RouteTableAssociation: Creation complete after 1s [id=rtbassoc-XXXX]
aws_route_table_association.PublicSubnet2RouteTableAssociation: Creation complete after 1s [id=rtbassoc-XXXX]
aws_lb.NetworkLoadBalancer: Still creating... [10s elapsed]
aws_autoscaling_group.ZillaPlusGroup: Still creating... [10s elapsed]
aws_autoscaling_group.ZillaPlusGroup: Creation complete after 12s [id=terraform-XXXX]
aws_lb.NetworkLoadBalancer: Still creating... [20s elapsed]
aws_lb.NetworkLoadBalancer: Still creating... [30s elapsed]
aws_lb.NetworkLoadBalancer: Still creating... [40s elapsed]
aws_lb.NetworkLoadBalancer: Still creating... [50s elapsed]
aws_lb.NetworkLoadBalancer: Still creating... [1m0s elapsed]
aws_lb.NetworkLoadBalancer: Still creating... [1m10s elapsed]
aws_lb.NetworkLoadBalancer: Still creating... [1m20s elapsed]
aws_lb.NetworkLoadBalancer: Still creating... [1m30s elapsed]
aws_lb.NetworkLoadBalancer: Still creating... [1m40s elapsed]
aws_lb.NetworkLoadBalancer: Still creating... [1m50s elapsed]
aws_lb.NetworkLoadBalancer: Still creating... [2m0s elapsed]
aws_lb.NetworkLoadBalancer: Still creating... [2m10s elapsed]
aws_lb.NetworkLoadBalancer: Still creating... [2m20s elapsed]
aws_lb.NetworkLoadBalancer: Still creating... [2m30s elapsed]
aws_lb.NetworkLoadBalancer: Still creating... [2m40s elapsed]
aws_lb.NetworkLoadBalancer: Still creating... [2m50s elapsed]
aws_lb.NetworkLoadBalancer: Creation complete after 2m55s [id=arn:aws:elasticloadbalancing:<region>:XXXX:loadbalancer/net/network-load-balancer/XXXX]
aws_lb_listener.NLBListener: Creating...
aws_lb_listener.NLBListener: Creation complete after 1s [id=arn:aws:elasticloadbalancing:<region>:XXXX:listener/net/network-load-balancer/XXXX/XXXX]

Apply complete! Resources: 17 added, 0 changed, 0 destroyed.

Outputs:

NetworkLoadBalancerOutput = "network-load-balancer-XXXX.elb.<region>.amazonaws.com"

```

### Configure Global DNS

This ensures that any new Kafka brokers added to the cluster can still be reached via the Zilla proxy. When using a wildcard DNS name for your own domain, such as `*.example.aklivity.io` then the DNS entries are setup in your DNS provider. After deploying the stack, check the outputs, where you can find the NetworkLoadBalancer DNS. `NetworkLoadBalancerOutput = "network-load-balancer-******.elb.us-east-1.amazonaws.com"` Lookup the IP addresses of your load balancer using `nslookup` and the DNS of the NetworkLoadBalancer.

```bash
nslookup network-load-balancer-******.elb.us-east-1.amazonaws.com
```

For testing purposes you can edit your local /etc/hosts file instead of updating your DNS provider. For example:

```bash
X.X.X.X  web.example.aklivity.io
```

### Test the Zilla Plus REST and SSE

If you added `web.example.aklivity.io` as the domain, open a terminal and use `curl` to open an SSE connection.

```bash
curl -N --http2 -H "Accept:text/event-stream" -v "https://web.example.aklivity.io:7143/<your path>"
```

Note that `your path` defaults to the exposed Kafka topic in your config.

In another terminal, use `curl` to POST and notice the data arriving on your SSE stream.

```bash
curl -d 'Hello, World' -X POST https://web.example.aklivity.io:7143/<your path>
```


## Destroy Stack using Terraform

```bash
terraform -chdir=cdktf.out/stacks/web-streaming destroy 
```
