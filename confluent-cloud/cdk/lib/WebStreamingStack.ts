import * as cdk from 'aws-cdk-lib';
import * as acm from 'aws-cdk-lib/aws-certificatemanager';
import * as autoscaling from 'aws-cdk-lib/aws-autoscaling';
import * as ec2 from 'aws-cdk-lib/aws-ec2';
import * as elbv2 from 'aws-cdk-lib/aws-elasticloadbalancingv2';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as secretsmanager from 'aws-cdk-lib/aws-secretsmanager';
import * as logs from 'aws-cdk-lib/aws-logs';
import * as route53 from 'aws-cdk-lib/aws-route53';
import { Construct } from 'constructs';
import * as path from 'path';
import Mustache = require("mustache");
import fs =  require("fs");
import { InterfaceVpcEndpointTarget } from 'aws-cdk-lib/aws-route53-targets';

interface TemplateData {
  name: string;
  vault: string;
  glue?: object;
  cloudwatch?: object;
  mappings?: Array<object>;
  public?: object;
  kafka?: object;
  jwt?: object;
}

interface WebStreamingVpcContext {
  cidr: string
}

interface WebStreamingSubnetsContext {
  public: WebStreamingSubnetContext,
  private: WebStreamingSubnetContext
}

interface WebStreamingSubnetContext {
  cidrMask: number
}

interface WebStreamingConfluentCloudContext {
  servers: string,
  credentials: string,
  privateLinkServiceId?: string
}

interface WebStreamingPublicContext {
  certificate: string,
  port?: number
}

interface WebStreamingMappingContext {
  topic: string;
  automatic: boolean;
  path?: string;
}

interface WebStreamingJWTContext {
  issuer: string,
  audience: string,
  keysUrl: string
}

interface WebStreamingCloudWatchContext {
  metrics?: WebStreamingCloudWatchMetricsContext,
  logs?: WebStreamingCloudWatchLogsContext
}

interface WebStreamingCloudWatchMetricsContext {
  namespace: string
}

interface WebStreamingCloudWatchLogsContext {
  group: string,
  stream?: string
}

interface WebStreamingContext {
  vpcId?: string,
  cidrs?: string[],
  peeringConnectionId?: string,
  vpc?: WebStreamingVpcContext,
  subnets?: WebStreamingSubnetsContext,
  confluentCloud: WebStreamingConfluentCloudContext;
  public: WebStreamingPublicContext;
  mappings: WebStreamingMappingContext[];
  jwt: WebStreamingJWTContext,
  glueRegistry?: string,
  cloudwatch?: WebStreamingCloudWatchContext,
  securityGroup?: string,
  roleName?: string,
  capacity?: number,
  instanceType?: string,
  sshKey?: string,
  ami?: string,
  version?: string
}

export class WebStreamingStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props?: cdk.StackProps) {
    super(scope, id, props);

    // lookup context
    const context = this.node.getContext(id) as WebStreamingContext;

    // detect dependencies
    const nitroEnclavesEnabled: boolean = context.public.certificate.startsWith("arn:aws:acm");
    const secretsmanagerEnabled: boolean = context.public.certificate.startsWith("arn:aws:secretsmanager");
    const cloudwatchEnabled: boolean =
      context.cloudwatch?.logs?.group !== undefined ||
      context.cloudwatch?.metrics?.namespace !== undefined;

    context.version ??= "latest";

    // apply context defaults
    context.capacity ??= 2;
    context.instanceType ??= nitroEnclavesEnabled ? 'c6i.xlarge' : 't3.small';

    const confluentBootstrapServers = context.confluentCloud.servers;
    const [kafkaHost, kafkaPort] = confluentBootstrapServers.split(',')[0].split(':');

    const internalPrivateLink = confluentBootstrapServers.split(".").includes("private");
    const internalVpcPeering = confluentBootstrapServers.split(".").includes("glb");

    // zilla.yaml template data
    const zillaYamlData: TemplateData = {
      name: 'public',
      vault: nitroEnclavesEnabled ? 'aws-acm' : 'aws-secrets',
      kafka: {},
      public: {},
      mappings: []
    };

    context.mappings ??= [];
    context.mappings.forEach((mapping: WebStreamingMappingContext) => {
      mapping.automatic ??= true;
      mapping.path ??= `/${mapping.topic}`;
    });


    context.vpc ??= { cidr: '10.0.0.0/16' };
    context.subnets ??= { private: { cidrMask: 24 }, public: { cidrMask: 24 } };

    let vpc;
    let subnets;
    if (internalVpcPeering) {
      vpc = ec2.Vpc.fromLookup(this, 'Vpc', { vpcId: context.vpcId });
      subnets = vpc.selectSubnets({
        subnetType: ec2.SubnetType.PUBLIC, 
        subnetFilters: [
            ec2.SubnetFilter.onePerAz()
        ]
      });

      if (subnets.isPendingLookup) {
        return;
      }

      const routeTableIds = new Set<string>();
      for (const subnet of subnets.subnets) {
        routeTableIds.add(subnet.routeTable.routeTableId);
      }

      let count = 0;
      context.cidrs ??= []
      for (const routeTableId of routeTableIds) {
        for (const cidr of context.cidrs) {
          new ec2.CfnRoute(this, `ConfluentRoute-${routeTableId}-${count++}`, {
            routeTableId,
            destinationCidrBlock: cidr,
            vpcPeeringConnectionId: context.peeringConnectionId
          });
        }
      }
    }
    else
    {
      vpc = new ec2.Vpc(this, 'ZillaPlus-Vpc', {
        ipAddresses: ec2.IpAddresses.cidr(context.vpc.cidr),
        maxAzs: 2,
        subnetConfiguration: [
          {
            cidrMask: context.subnets?.private.cidrMask,
            name: 'ZillaPlus-Private',
            subnetType: ec2.SubnetType.PRIVATE_ISOLATED
          },
          {
            cidrMask: context.subnets?.public.cidrMask,
            name: 'ZillaPlus-Public',
            subnetType: ec2.SubnetType.PUBLIC
          },
        ],
      });
      subnets = vpc.selectSubnets({
        subnetType: ec2.SubnetType.PUBLIC, 
        subnetFilters: [
            ec2.SubnetFilter.onePerAz()
        ]
      });
    }

    const publicPort = context.public.port ?? 7143;

    let securityGroup;

    if (context.securityGroup) {
      securityGroup =
        ec2.SecurityGroup.fromLookupById(this, `ZillaPlus-SecurityGroup`, context.securityGroup);
    }
    else {
      securityGroup = new ec2.SecurityGroup(this, 'ZillaPlus-SecurityGroup', {
        securityGroupName: `zilla-plus-${id}`,
        description: `Zilla Plus Security Group`,
        vpc: vpc,
      });

      securityGroup.addIngressRule(
        ec2.Peer.anyIpv4(),
        ec2.Port.tcp(Number(publicPort)),
        'Allow inbound traffic on Web Streaming port');
    }

    if (internalPrivateLink) {
      const vpcEndpoint = vpc.addInterfaceEndpoint(`ZillaPlus-PrivateLinkEndpoint`, {
        service: new ec2.InterfaceVpcEndpointService(context.confluentCloud.privateLinkServiceId ?? "", Number(kafkaPort)),
        subnets: subnets,
        securityGroups: [securityGroup]
      });

      new cdk.CfnOutput(this, 'PrivateLinkVpcEndpointId', 
      { 
        description: "Private Link VPC Endpoint Id",
        value: vpcEndpoint.vpcEndpointId
      });

      const hostedZone = new route53.PrivateHostedZone(this, 'ZillaPlus-HostedZone', {
        vpc: vpc,
        zoneName: kafkaHost.split('.').slice(1).join(".")
      });
  
      new route53.RecordSet(this, 'Client-HostedZoneRecords', {
        zone: hostedZone,
        recordType: route53.RecordType.A,
        recordName: '*',
        target: route53.RecordTarget.fromAlias(new InterfaceVpcEndpointTarget(vpcEndpoint))
      });
  
      cdk.Tags.of(hostedZone).add('Name', `ZillaPlus-${id}`);
    }

    let role;

    if (!context.roleName) {
      role = new iam.Role(this, `ZillaPlus-Role`, {
        roleName: `zilla-plus-${id}`,
        assumedBy: new iam.CompositePrincipal(
          new iam.ServicePrincipal('ec2.amazonaws.com'),
          new iam.ServicePrincipal('cloudformation.amazonaws.com')
        ),
        managedPolicies: [
          iam.ManagedPolicy.fromAwsManagedPolicyName('AmazonSSMManagedInstanceCore'),
          iam.ManagedPolicy.fromAwsManagedPolicyName('AWSCertificateManagerReadOnly'),
          iam.ManagedPolicy.fromAwsManagedPolicyName('AWSGlueSchemaRegistryReadonlyAccess'),
          iam.ManagedPolicy.fromAwsManagedPolicyName('CloudWatchLogsFullAccess'),
        ],
        inlinePolicies: {
          ZillaPlusSecretsManagerRead: new iam.PolicyDocument({
            statements: [
              new iam.PolicyStatement({
                effect: iam.Effect.ALLOW,
                actions: [
                  'acm-pca:GetCertificate',
                  'acm-pca:GetCertificateAuthorityCertificate',
                  'acm-pca:DescribeCertificateAuthority',
                  'tag:GetResources',
                  'secretsmanager:GetSecretValue',
                  'secretsmanager:DescribeSecret',
                ],
                resources: [
                  '*',
                ],
              }),
            ],
          }),
        },
      });

      const iamPolicy = new iam.PolicyDocument({
        statements: [
          new iam.PolicyStatement({
            effect: iam.Effect.ALLOW,
            actions: ['secretsmanager:GetSecretValue', 'secretsmanager:DescribeSecret'],
            resources: ['arn:aws:secretsmanager:*:*:secret:*'],
          })
        ],
      });

      if (cloudwatchEnabled) {
        iamPolicy.addStatements(
          new iam.PolicyStatement({
            effect: iam.Effect.ALLOW,
            actions: ['logs:*', 'cloudwatch:GenerateQuery', 'cloudwatch:PutMetricData'],
            resources: ['*'],
          }));
      }

      if (nitroEnclavesEnabled) {
        const association = new ec2.CfnEnclaveCertificateIamRoleAssociation(this, `ZillaPlus-EnclaveCertificateIamRoleAssociation`, {
          certificateArn: context.public.certificate,
          roleArn: role.roleArn,
        });

        iamPolicy.addStatements(
          new iam.PolicyStatement({
            effect: iam.Effect.ALLOW,
            actions: ['s3:GetObject'],
            resources: [`arn:aws:s3:::${association.attrCertificateS3BucketName}/*`],
          }),
          new iam.PolicyStatement({
            effect: iam.Effect.ALLOW,
            actions: ['kms:Decrypt'],
            resources: [`arn:aws:kms:${this.region}:*:key/${association.attrEncryptionKmsKeyId}`],
          }),
          new iam.PolicyStatement({
            effect: iam.Effect.ALLOW,
            actions: ['iam:GetRole'],
            resources: [`*`],
          })
        );
      }

      new iam.Policy(this, `ZillaPlus-Policy`, {
        policyName: `ZillaPlus-${id}`,
        roles: [role],
        document: iamPolicy
      });
    }

    if (context.cloudwatch) {
      zillaYamlData.cloudwatch = {};

      const logGroup = context.cloudwatch?.logs?.group;
      if (logGroup) {
        const group = logs.LogGroup.fromLogGroupName(this, `LogGroup-$logGroup`, logGroup);
        const stream = context.cloudwatch?.logs?.stream ?? 'events';

        zillaYamlData.cloudwatch = {
          ...zillaYamlData.cloudwatch,
          logs: {
            group: group.logGroupName,
            stream: stream
          }
        }
      }
  
      const metricsNamespace = context.cloudwatch?.metrics?.namespace;
      if (metricsNamespace) {
        zillaYamlData.cloudwatch = {
          ...zillaYamlData.cloudwatch,
          metrics: {
            namespace: metricsNamespace,
          },
        };
      }
    }

    const jwt = context.jwt;
    if (jwt)
    {
      zillaYamlData.jwt = {
        issuer: jwt.issuer,
        audience: jwt.audience,
        keysUrl: jwt.keysUrl
      }
    }

    const glueRegistry = context.glueRegistry;
    if (glueRegistry)
    {
      zillaYamlData.glue = {
        registry: glueRegistry
      }
    }

    zillaYamlData.public = {
      ...zillaYamlData.public,
      certificate: context.public.certificate,
      port: Number(publicPort)
    }

    const credentialsSecretName = context.confluentCloud.credentials;

    const kafkaSaslUsername = `\${{aws.secrets.${credentialsSecretName}#username}}`;
    const kafkaSaslPassword = `\${{aws.secrets.${credentialsSecretName}#password}}`;
    const kafkaBootstrapServers = `['${confluentBootstrapServers.split(",").join("','")}']`;

    zillaYamlData.kafka = {
      ...zillaYamlData.kafka,
      servers: kafkaBootstrapServers,
      sasl : {
        username: kafkaSaslUsername,
        password: kafkaSaslPassword
      }
    }


    zillaYamlData.mappings = context.mappings;

    let userdataData = {
      stack: `${id}`,
      region: `${this.region}`,
      yaml: {}
    }

    if (nitroEnclavesEnabled) {
      const acmYamlData = {
        external: {
          certificate: context.public.certificate
        }
      }
      const acmYaml = this.renderMustache('acm.yaml.mustache', acmYamlData);

      userdataData.yaml = {
        ...userdataData.yaml,
        acm: acmYaml
      }
    }

    const zillaYamlPath = path.resolve(__dirname, '../zilla.yaml');
    const zillaYaml: string = fs.existsSync(zillaYamlPath)
      ? fs.readFileSync(zillaYamlPath, 'utf-8')
      : this.renderMustache('WebStreaming/zilla.yaml.mustache', zillaYamlData);

    userdataData.yaml = {
      ...userdataData.yaml,
      zilla: zillaYaml
    }
    const userdata: ec2.UserData = ec2.UserData.custom(this.renderMustache('userdata.mustache', userdataData));

    const autoTopics: string[] = context.mappings
      .filter((mapping: { automatic: boolean; }) => mapping.automatic)
      .map((mapping: { topic: any; }) => mapping.topic);

    if (autoTopics.length > 0)
    {
      userdata.addCommands(
        `wget https://archive.apache.org/dist/kafka/3.5.1/kafka_2.13-3.5.1.tgz`,
        `tar -xzf kafka_2.13-3.5.1.tgz`,
        `cd kafka_2.13-3.5.1`,
        `SECRET_STRING=$(aws secretsmanager get-secret-value \
          --secret-id ${context.confluentCloud.credentials} \
          --query SecretString \
          --output text)`,
        `USERNAME=$(echo $SECRET_STRING | jq -r '.username')`,
        `PASSWORD=$(echo $SECRET_STRING | jq -r '.password')`,

        `cat <<EOF> client.properties`,
        `sasl.jaas.config=org.apache.kafka.common.security.scram.ScramLoginModule required username='$USERNAME' password='$PASSWORD';`,
        `security.protocol=SASL_SSL`,
        `sasl.mechanism=PLAIN`,
        `EOF`);

      autoTopics.forEach((topic: string) =>
        userdata.addCommands(
          `./bin/kafka-topics.sh \
            --bootstrap-server ${context.confluentCloud.servers} \
            --command-config client.properties \
            --create --if-not-exists \
            --topic ${topic} \
            --partitions 3 \
            --config 'cleanup.policy=compact'`));

      userdata.addCommands(
          `rm client.properties`
      );
    }

    if (secretsmanagerEnabled) {
      secretsmanager.Secret.fromSecretNameV2(this, 'ZillaPlus-SecretsCertificate', context.public.certificate);
    }

    if (nitroEnclavesEnabled) {
      acm.Certificate.fromCertificateArn(this, 'ZillaPlus-AcmCertificate', context.public.certificate);
    }

    const machineImage = context.ami
    ? ec2.MachineImage.genericLinux({
        [cdk.Stack.of(this).region]: context.ami
      })
    : ec2.MachineImage.fromSsmParameter(`/aws/service/marketplace/prod-e7nsxirtspuaa/${context.version}`);
    
    const keyPair = context.sshKey ? ec2.KeyPair.fromKeyPairName(this, `ZillaPlus-KeyPair`, context.sshKey) : undefined;

    const launchTemplate = new ec2.LaunchTemplate(this, `ZillaPlus-LaunchTemplate`, {
      machineImage: machineImage,
      instanceType: new ec2.InstanceType(context.instanceType),
      role: role,
      associatePublicIpAddress: true,
      nitroEnclaveEnabled: nitroEnclavesEnabled,
      securityGroup: securityGroup,
      keyPair: keyPair,
      userData: userdata
    });

    const loadBalancer = new elbv2.NetworkLoadBalancer(this, `ZillaPlus-LoadBalancer`, {
      internetFacing: true, // Internet Facing
      ipAddressType: elbv2.IpAddressType.IPV4,
      vpc: vpc,
      vpcSubnets: subnets,
      securityGroups: [securityGroup],
      // enforceSecurityGroupInboundRulesOnPrivateLinkTraffic: false
    });

    const targetGroup = new elbv2.NetworkTargetGroup(this, `ZillaPlus-TargetGroup`, {
      protocol: elbv2.Protocol.TCP,
      port: Number(publicPort),
      vpc: vpc,
      targetType: elbv2.TargetType.INSTANCE
    });

    loadBalancer.addListener(`TCP-${publicPort}`, {
      port: Number(publicPort),
      protocol: elbv2.Protocol.TCP,
      defaultAction: elbv2.NetworkListenerAction.forward([targetGroup])
    })

    const autoScalingGroup = new autoscaling.AutoScalingGroup(this, `ZillaPlus-AutoScalingGroup`, {
      vpc: vpc,
      vpcSubnets: subnets,
      launchTemplate: launchTemplate,
      minCapacity: context.capacity,
      maxCapacity: 5,
    });

    autoScalingGroup.attachToNetworkTargetGroup(targetGroup);

    cdk.Tags.of(launchTemplate).add('Name', `ZillaPlus-${id}`);

    new cdk.CfnOutput(this, 'LoadBalancerDnsName', 
      { 
        description: "NetworkLoadBalancer DNS name",
        value: loadBalancer.loadBalancerDnsName
      });
  }

  private renderMustache(filename: string, data: object): string
  {
    const mustache: string = path.resolve(__dirname, `templates/${filename}`);
    const template: string = fs.readFileSync(mustache, 'utf8');
    return Mustache.render(template, data);
  }
}
