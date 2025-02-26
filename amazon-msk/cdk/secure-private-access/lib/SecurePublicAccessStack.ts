import * as cdk from 'aws-cdk-lib';
import * as acm from 'aws-cdk-lib/aws-certificatemanager';
import * as autoscaling from 'aws-cdk-lib/aws-autoscaling';
import * as ec2 from 'aws-cdk-lib/aws-ec2';
import * as elbv2 from 'aws-cdk-lib/aws-elasticloadbalancingv2';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as secretsmanager from 'aws-cdk-lib/aws-secretsmanager';
import * as logs from 'aws-cdk-lib/aws-logs';
import { Construct } from 'constructs';
import * as path from 'path';
import Mustache = require("mustache");
import fs =  require("fs");

interface TemplateData {
  name: string;
  vault: string;
  cloudwatch?: object;
  internal?: object;
  external?: object;
}

interface SecurePublicAccessInternalContext {
  servers: string,
  trust: string
}

interface SecurePublicAccessExternalContext {
  servers: string,
  certificate: string,
  trust: string
}

interface SecurePublicAccessCloudWatchContext {
  metrics?: SecurePublicAccessCloudWatchMetricsContext,
  logs?: SecurePublicAccessCloudWatchLogsContext
}

interface SecurePublicAccessCloudWatchMetricsContext {
  namespace: string
}

interface SecurePublicAccessCloudWatchLogsContext {
  group: string,
  stream?: string
}

interface SecurePublicAccessContext {
  vpcId: string,
  subnetIds: Array<string>,
  internal: SecurePublicAccessInternalContext;
  external: SecurePublicAccessExternalContext;
  cloudwatch?: SecurePublicAccessCloudWatchContext,
  securityGroup?: string,
  roleName?: string,
  capacity?: number,
  instanceType?: string,
  sshKey?: string,
  ami?: string
}

export class SecurePublicAccessStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props?: cdk.StackProps) {
    super(scope, id, props);

    // lookup context
    const context = this.node.getContext(id) as SecurePublicAccessContext;

    // detect dependencies
    const nitroEnclavesEnabled: boolean = context.external.certificate.startsWith("arn:aws:acm");
    const secretsmanagerEnabled: boolean = context.external.certificate.startsWith("arn:aws:secretsmanager");
    const cloudwatchEnabled: boolean =
      context.cloudwatch?.logs?.group !== undefined ||
      context.cloudwatch?.metrics?.namespace !== undefined;

    // apply context defaults
    context.capacity ??= 2;
    context.instanceType ??= nitroEnclavesEnabled ? 'c6i.xlarge' : 't3.small';
    context.external.trust ??= context.internal.trust;

    const [internalServer, internalPort] = context.internal.servers.split(',')[0].split(':');
    const internalWildcardDNS = `*.${internalServer.split('.').slice(1).join(".")}`;

    const [externalServer, externalPort] = context.external.servers.split(',')[0].split(':');
    const externalWildcardDNS = `*.${externalServer.split('.').slice(1).join(".")}`;

    // zilla.yaml template data
    const zillaYamlData: TemplateData = {
      name: 'private',
      vault: nitroEnclavesEnabled ? 'aws-acm' : 'aws-secrets',
      internal: {},
      external: {}
    };

    let endpoints: Record<string, ec2.InterfaceVpcEndpointAwsService> = {};

    /*
    endpoints = {
      ...endpoints,
      "ssm": ec2.InterfaceVpcEndpointAwsService.SSM,
      "cloudformation": ec2.InterfaceVpcEndpointAwsService.CLOUDFORMATION,
      "ssm_messages": ec2.InterfaceVpcEndpointAwsService.SSM_MESSAGES,
      "ec2_messages": ec2.InterfaceVpcEndpointAwsService.EC2_MESSAGES,
    };
    
    if (secretsmanagerEnabled) {
      endpoints = {
        ...endpoints,
        "secretsmanager": ec2.InterfaceVpcEndpointAwsService.SECRETS_MANAGER,
      };
    }

    if (cloudwatchEnabled)
    {
      endpoints = {
        ...endpoints,
        "monitoring": ec2.InterfaceVpcEndpointAwsService.CLOUDWATCH_MONITORING,
        "cloudwatch": ec2.InterfaceVpcEndpointAwsService.CLOUDWATCH_LOGS,
      };
    }

    if (nitroEnclavesEnabled) {
      endpoints = {
        ...endpoints,
        "acm-pca": ec2.InterfaceVpcEndpointAwsService.PRIVATE_CERTIFICATE_AUTHORITY,
        "kms": ec2.InterfaceVpcEndpointAwsService.KMS,
        "s3": ec2.InterfaceVpcEndpointAwsService.S3,
        "iam": ec2.InterfaceVpcEndpointAwsService.IAM
      }
    }
    */

    const vpc = ec2.Vpc.fromLookup(this, 'Vpc', { vpcId: context.vpcId });
    const subnets = vpc.selectSubnets({
      subnetType: ec2.SubnetType.PUBLIC, 
      subnetFilters: [ec2.SubnetFilter.byIds(context.subnetIds)]
    });

    if (subnets.isPendingLookup) {
      return;
    }

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
        ec2.Port.tcp(Number(externalPort)),
        'Allow inbound traffic on Kafka IAM port');
    }

    for (const serviceName in endpoints) {
      if (endpoints.hasOwnProperty(serviceName)) {
        if (serviceName == "s3") {
          vpc.addGatewayEndpoint("Endpoint-s3-gateway", {
            service: ec2.GatewayVpcEndpointAwsService.S3,
            subnets: [subnets],
          });
        }

        const service = endpoints[serviceName as keyof typeof endpoints];
        vpc.addInterfaceEndpoint(`Endpoint-${serviceName}`, {
          service: service,
          subnets: subnets,
          securityGroups: [securityGroup]
        });
      }
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
          iam.ManagedPolicy.fromAwsManagedPolicyName('CloudWatchLogsFullAccess'),
        ],
        inlinePolicies: {
          CCProxySecretsManagerRead: new iam.PolicyDocument({
            statements: [
              new iam.PolicyStatement({
                sid: 'VisualEditor0',
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
            sid: 'secretStatement',
            effect: iam.Effect.ALLOW,
            actions: ['secretsmanager:GetSecretValue', 'secretsmanager:DescribeSecret'],
            resources: ['arn:aws:secretsmanager:*:*:secret:*'],
          })
        ],
      });

      if (cloudwatchEnabled) {
        iamPolicy.addStatements(
          new iam.PolicyStatement({
            sid: 'cloudwatchStatement',
            effect: iam.Effect.ALLOW,
            actions: ['logs:*', 'cloudwatch:GenerateQuery', 'cloudwatch:PutMetricData'],
            resources: ['*'],
          }));
      }

      if (nitroEnclavesEnabled) {
        const association = new ec2.CfnEnclaveCertificateIamRoleAssociation(this, `ZillaPlus-EnclaveCertificateIamRoleAssociation`, {
          certificateArn: context.external.certificate,
          roleArn: role.roleArn,
        });

        iamPolicy.addStatements(
          new iam.PolicyStatement({
            sid: 's3Statement',
            effect: iam.Effect.ALLOW,
            actions: ['s3:GetObject'],
            resources: [`arn:aws:s3:::${association.attrCertificateS3BucketName}/*`],
          }),
          new iam.PolicyStatement({
            sid: 'kmsDecryptStatement',
            effect: iam.Effect.ALLOW,
            actions: ['kms:Decrypt'],
            resources: [`arn:aws:kms:${this.region}:*:key/${association.attrEncryptionKmsKeyId}`],
          }),
          new iam.PolicyStatement({
            sid: 'getRoleStatement',
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

    const externalDomain = externalWildcardDNS.split("*.")[1];
    const externalHost = `b-#.${externalDomain}`;

    const internalServerless = internalWildcardDNS.split(".").includes("serverless");

    const internalDomain = internalServerless
      ? internalWildcardDNS.split("*-")[1]
      : internalWildcardDNS.split("*.")[1];

    const internalHost = internalServerless
      ? `b#-${internalDomain}`
      : `b-#.${internalDomain}`;

    const internalDefault = internalServerless
      ? `boot-${internalDomain}`
      : undefined;

    zillaYamlData.external = {
      ...zillaYamlData.external,
      certificate: context.external.certificate,
      trust: context.external.trust,
      authority: externalWildcardDNS,
      host: externalHost,
      port: Number(externalPort)
    }

    zillaYamlData.internal = {
      ...zillaYamlData.internal,
      trust: context.internal.trust,
      authority: internalWildcardDNS,
      host: internalHost,
      port: Number(internalPort),
      defaultHost: internalDefault
    }

    let userdataData = {
      stack: `${id}`,
      region: `${this.region}`,
      yaml: {}
    }

    if (nitroEnclavesEnabled) {
      const acmYamlData = {
        external: {
          certificate: context.external.certificate
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
      : this.renderMustache('SecureAccess/zilla.yaml.mustache', zillaYamlData);

    userdataData.yaml = {
      ...userdataData.yaml,
      zilla: zillaYaml
    }

    const userdata: string = this.renderMustache('userdata.mustache', userdataData);

    if (secretsmanagerEnabled) {
      secretsmanager.Secret.fromSecretNameV2(this, 'ZillaPlus-SecretsCertificate', context.external.certificate);
    }

    if (nitroEnclavesEnabled) {
      acm.Certificate.fromCertificateArn(this, 'ZillaPlus-AcmCertificate', context.external.certificate);
    }

    const machineImage = context.ami ?
      ec2.MachineImage.genericLinux({
        [`${cdk.Arn.extractResourceName(context.ami, 'region')}`]: context.ami
      })
      : ec2.MachineImage.lookup({
          name: 'Aklivity Zilla Plus *',
          filters: {
            'product-code': ['ca5mgk85pjtbyuhtfluzisgzy'],
            'is-public': ['true'],
          },
        });

    const keyPair = context.sshKey ? ec2.KeyPair.fromKeyPairName(this, `ZillaPlus-KeyPair`, context.sshKey) : undefined;

    const launchTemplate = new ec2.LaunchTemplate(this, `ZillaPlus-LaunchTemplate`, {
      machineImage: machineImage,
      instanceType: new ec2.InstanceType(context.instanceType),
      role: role,
      nitroEnclaveEnabled: nitroEnclavesEnabled,
      securityGroup: securityGroup,
      keyPair: keyPair,
      userData: ec2.UserData.custom(userdata)
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
      port: Number(externalPort),
      vpc: vpc,
      targetType: elbv2.TargetType.INSTANCE
    });

    loadBalancer.addListener(`TCP-${externalPort}`, {
      port: Number(externalPort),
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

    new cdk.CfnOutput(this, 'CustomDnsWildcard', 
      { 
        description: "Custom DNS wildcard",
        value: externalWildcardDNS
      });

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
