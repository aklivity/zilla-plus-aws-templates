# Secure Public Access deploy via CDK

This guide will help you gather the necessary AWS values required to configure and deploy Zilla Plus Secure Public Access using CDK.

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

## (optional) Create an example MSK cluster

If you don't have an existing MSK cluster you can use our example MSK deployment with basic configuration and Unauthorized access. Follow the instructions inside the [example-cluster](../example-cluster/README.md) folder to deploy the example MSK cluster. Note the `MskClusterArn` from the outputs as you'll need this later. You will need to set the MSK client auth method variable to the desired one that is set up for the MSK cluster.

## Required CDK Context Variables

You can set these variables in your `context` in `cdk.json` file under `zilla-plus` object.

### `vpcId`: VPC ID
The VPC ID where the MSK cluster lives. The stack will add Public Subnets and Internet Gateway and run Zilla Plus on the provided VPC.

```bash
aws ec2 describe-subnets --subnet-ids $(aws kafka describe-cluster --cluster-arn <msk-cluster-arn> --query "ClusterInfo.BrokerNodeGroupInfo.ClientSubnets[0]" --output text) --query "Subnets[0].VpcId" --output text
```

### `msk` related variables

```json
    "msk":
    {
        "servers": "<Bootstrap Servers of your MSK cluster",
        "clientAuthentication": "<MSK client authentication method: [mTLS, SASL/SCRAM or Unauthorized]>"
    }
```

#### `servers`: MSK Bootstrap Servers and Authentication Method

To get the bootstrap servers of the MSK cluster run:

```bash
aws kafka get-bootstrap-brokers \
    --cluster-arn <msk-cluster-arn> \
    --query '{BootstrapBrokerStringTls: BootstrapBrokerStringTls, BootstrapBrokerStringSaslScram: BootstrapBrokerStringSaslScram, BootstrapBrokerStringSaslIam: BootstrapBrokerStringSaslIam}' \
    --output table
```

Use the `Bootstrap Server` of your desired authentication method to set the `servers` variable.
Set the desired client authentication method based on the MSK cluster setup, using `clientAuthentication` variable. Allowed values are: `SASL/SCRAM`, `mTLS`, `Unauthorized`.

### `public` Zilla Plus variables

```json
    "public":
    {
        "wildcardDNS": "<your public wildcard dns>",
        "certificate": "<your public tls certificate key ARN>",
        "port": "<your public port>"
    }
```

#### `wildcardDNS`: Public Wildcard DNS

This variable defines the public wildcard DNS pattern for bootstrap servers to be used by Kafka clients.
It should match the wildcard DNS of the public TLS certificate.

#### `certificate`: Public TLS Certificate Key

You need the ARN of either the Certificte Manager certificate or the Secrets Manager secret that contains your public TLS certificate private key.

List all certificates in Certificate Manager:

```bash
aws acm list-certificates --certificate-statuses ISSUED --query 'CertificateSummaryList[*].[DomainName,CertificateArn]' --output table
```

Find and note down the ARN of your public TLS certificate.

List all secrets in Secrets Manager:

```bash
aws secretsmanager list-secrets --query 'SecretList[*].[Name,ARN]' --output table
```

Find and note down the ARN of the secret that contains your public TLS certificate private key.

#### `port`: Public TCP Port

> Default: `9094`

This variable defines the public port number to be used by Kafka clients.


### `capacity`: Zilla Plus Capacity

> Default: `2`

This variable defines the initial number of Zilla Plus instances.

### `instanceType`: Zilla Plus EC2 Instance Type

> Default: `t3.small`

This variable defines the initial number of Zilla Plus instances.

### mTLS Specific Variables

You only need to add these if you choose mTLS as client authentication method

#### `certificateAuthorityArn`: MSK Certificate Authority ARN

This variable defines the ACM Private Certificate Authority ARN used to authorize clients connecting to the MSK cluster. You can set this in the context variable in your `cdk.json` file under `zilla-plus` object in the `msk` variables section.

List all ACM Private Certificate Authorities:

```bash
aws acm-pca list-certificate-authorities --query 'CertificateAuthorities[*].[Arn]' --output table
```

Note down the ARN of the ACM Private Certificate Authority you want to use.

## Optional Features

These features all have default values and can be configured using cdk context variables. If you don't plan to configure any of these features you can skip this section and go to the [Deploy stack using CDK](#deploy-stack-using-cdk) section.

### Internet Gateway ID

If you already have an Internet Gateway in the MSK's VPN it should be provided via the `igwId` context variable in your `cdk.json` under `zilla-plus` object. If not set the deployment will attempt to create on in the VPC.

To query the igwId of your MSK's VPN use the following command:
```bash
VPC_ID=$(aws kafka describe-cluster --cluster-arn <msk-cluster-arn> --query "ClusterInfo.VpcConfig.VpcId" --output text)
aws ec2 describe-internet-gateways --filters "Name=attachment.vpc-id,Values=$VPC_ID" --query "InternetGateways[0].InternetGatewayId" --output text
```

### Public TLS Certificate via AWS Certificate Manager for Nitro Enclaves

If you want to enable Zilla-plus Nitro Enclaves support all you have to do is provide the `public.certificate` context variable via ACM.

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

### Separate Public Certificate Authority ARN

This variable defines the ACM Private Certificate Authority ARN used to authorize clients connecting to the Public Zilla Plus.
By default Zilla Plus will use the `msk.certificateAuthorityArn` for the Public Certificate Authority. If you want to change this set `certificateAuthorityArn` context variable in your `cdk.json` file under `zilla-plus` object in the `public` variables section.

List all ACM Private Certificate Authorities:

```bash
aws acm-pca list-certificate-authorities --query 'CertificateAuthorities[*].[Arn]' --output table
```

Note down the ARN of the ACM Private Certificate Authority you want to use.

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

### Configure Global DNS

This ensures that any new Kafka brokers added to the cluster can still be reached via the Zilla proxy. When using a wildcard DNS name for your own domain, such as `*.example.aklivity.io` then the DNS entries are setup in your DNS provider. After deploying the stack, check the outputs, where you can find the NetworkLoadBalancer DNS.
```
NetworkLoadBalancerOutput = "network-load-balancer-******.elb.us-east-1.amazonaws.com"
```
Lookup the IP addresses of your load balancer using `nslookup` and the DNS of the NetworkLoadBalancer.

```bash
nslookup network-load-balancer-86334a80cbd16ec2.elb.us-east-2.amazonaws.com
```

For testing purposes you can edit your local /etc/hosts file instead of updating your DNS provider.

#### DNS setup for MSK Serverless
MSK Serverless requires you to add ALL the advertised host names in your DNS resolver. We recommend to use `dnsmasq` for local setup.

**Install dnsmasq**

```bash
sudo apt update && sudo apt install dnsmasq -y
```

**Configure it to resolve all b-*.example.aklivity.io to a specific IP.** 

Edit /etc/dnsmasq.conf and add:

```text
address=/b-/.example.aklivity.io/<your NLB IP address>
address=boot.example.aklivity.io/<your NLB IP address>
```

**Restart dnsmasq**
```bash
sudo systemctl restart dnsmasq
```

**Ensure your system uses dnsmasq for lookups**

 Check `/etc/resolv.conf` and set:
```text
nameserver 127.0.0.1
```

### Install the Kafka Client

First, we must install a Java runtime that can be used by the Kafka client.

```bash
sudo yum install java-1.8.0
```

Now we are ready to install the Kafka client:

```bash
wget https://archive.apache.org/dist/kafka/2.8.0/kafka_2.13-2.8.0.tgz
tar -xzf kafka_2.13-2.8.0.tgz
cd kafka_2.13-2.8.0
```

### Configure the Kafka Client

With the Kaka client now installed we are ready to configure it and point it at the Zilla proxy.

#### mTLS

If you configured Zilla Plus to use mTLS authentication method, we need to import the trusted client certificate and corresponding private key into the local key store used by the Kafka client when connecting to the Zilla proxy. Also first you need to create a client certificate.

##### Create client certificate

You can use the following script to create a client certificate signed by an AWS Private Certificate Authority and upload the client private key to AWS SecretsManager.

<details>

<summary>create_client_certificate.sh</summary>

```bash
#!/bin/bash

while [ $# -gt 0 ]; do
    if [[ $1 == "--"* ]]; then
        v="${1/--/}"
        v="${v//-/$'_'}"
        declare "$v"="$2"
        shift
    fi
    shift
done

programname=$0

function usage {
    echo ""
    echo "Creates signed client certificate and uploads client private key to SecretsManager"
    echo ""
    echo "usage: $programname --client-name string  --acm-pca-certificate-authority string"
    echo ""
    echo "  --client-name string                         name of the client"
    echo "                                               (example: client-1)"
    echo "  --acm-pca-certificate-authority string       AWS private certificate authority arn"
    echo "                                               (example: arn:aws:acm-pca:us-east-1..:certificate-authority)"
    echo ""
}

function die {
    printf "Script failed: %s\n\n" "$1"
    exit 1
}

if [[ -z $client_name ]]; then
    usage
    die "Missing parameter --client-name"
elif [[ -z $acm_pca_certificate_authority ]]; then
    usage
    die "Missing parameter --acm-pca-certificate-authority"
fi

set -ex

openssl genrsa -out "$client_name".key.pem 4096
openssl pkcs8 -topk8 -nocrypt -in "$client_name".key.pem -out "$client_name".pkcs8.pem

openssl req -new -key "$client_name".key.pem -out "$client_name".csr

aws acm-pca issue-certificate \
  --region us-east-1 \
  --certificate-authority-arn "$acm_pca_certificate_authority" \
  --csr fileb://"$client_name".csr \
  --signing-algorithm "SHA256WITHRSA" \
  --validity Value=365,Type="DAYS" \
  --idempotency-token 1234 > "$client_name".json

clientCertArn=$(jq -r '.CertificateArn' "$client_name".json)

aws secretsmanager create-secret \
  --region us-east-1 \
  --name "$client_name" \
  --secret-string file://"$client_name".pkcs8.pem \
  --tags "[{\"Key\":\"certificate-authority-arn\", \"Value\":\"$acm_pca_certificate_authority\"}, {\"Key\":\"certificate-arn\", \"Value\": \"$clientCertArn\"}]"

aws acm-pca get-certificate \
  --region us-east-1 \
  --certificate-arn "$clientCertArn" \
  --certificate-authority-arn "$acm_pca_certificate_authority" \
  --output text | sed "s/\t/\n/g" > "$client_name".cert

```

</details>

##### Import trusted client certificate

```bash
openssl pkcs12 -export -in client-1.cert -inkey client-1.pkcs8.pem -out client-1.p12 -name client-1
keytool -importkeystore -destkeystore /tmp/kafka.client.keystore.jks -deststorepass generated -srckeystore client-1.p12 -srcstoretype PKCS12 -srcstorepass generated -alias client-1
```

In this example, we are importing a private key and certificate with Common Name client-1 signed by a private certificate authority. First the private key and signed certificate are converted into a p12 formatted key store.

Then the key store is converted to /tmp/kafka.client.keystore.jks in JKS format. When prompted, use a consistent password for each command. We use the password generated to illustrate these steps.

The Zilla proxy relies on TLS so we need to create a file called client.properties that tells the Kafka client to use SSL as the security protocol and to specify the key store containing authorized client certificates.

##### client.properties

```text
security.protocol=SSL
ssl.keystore.location=/tmp/kafka.client.keystore.jks
ssl.keystore.password=generated
```

#### SASL/SCRAM

If you configured Zilla Plus to use SASL/SCRAM authentication method, Zilla proxy relies on encrypted SASL/SCRAM so we need to create a file called client.properties that tells the Kafka client to use SASL_SSL as the security protocol with SCRAM-SHA-512 encryption.

Notice we used the default username and password, but you will need to replace those with your own credentials from the `AmazonMSK_*` secret you created.

##### client.properties

```text
sasl.jaas.config=org.apache.kafka.common.security.scram.ScramLoginModule required username="alice" password="alice-secret";
security.protocol=SASL_SSL
sasl.mechanism=SCRAM-SHA-512
```

#### Unauthorized

##### Trust the Private Certificate Authority

Import the private CA certificate into your trust store.

```bash
keytool -importcert -keystore /tmp/kafka.client.truststore.jks -storetype jks -storepass generated -alias pca -file Certificate.pem
```

##### Configure the Kafka Client

The Zilla proxy relies on TLS so we need to create a file called client.properties that tells the Kafka client to use SSL as the security protocol and to trust your private certificate authority as the signer of the \*.aklivity.example.com certificate.

##### client.properties

```text
security.protocol=SSL
ssl.truststore.location=/tmp/kafka.client.truststore.jks
```

### Test the Kafka Client

This verifies internet connectivity to your MSK cluster via Zilla Plus for Amazon MSK.

We can now verify that the Kafka client can successfully communicate with your MSK cluster via the internet from your local development environment to create a topic, then publish and subscribe to the same topic.

If using the wildcard DNS pattern `*.example.aklivity.io`, then we use the following as TLS bootstrap server names for the Kafka client:

```text
b-1.example.aklivity.io:9094,b-2.example.aklivity.io:9094
```

Replace these TLS bootstrap server names accordingly for your own custom wildcard DNS pattern.

#### Create a Topic

Use the Kafka client to create a topic called zilla-proxy-test, replacing <tls-bootstrap-server-names> in the command below with the TLS proxy names of your Zilla proxy:

```bash
bin/kafka-topics.sh --create --topic zilla-proxy-test --partitions 3 --replication-factor 2 --command-config client.properties --bootstrap-server <tls-bootstrap-server-names>
```
