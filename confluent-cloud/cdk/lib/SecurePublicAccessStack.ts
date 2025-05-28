import * as cdk from 'aws-cdk-lib';
import * as acm from 'aws-cdk-lib/aws-certificatemanager';
import * as autoscaling from 'aws-cdk-lib/aws-autoscaling';
import * as ec2 from 'aws-cdk-lib/aws-ec2';
import * as elbv2 from 'aws-cdk-lib/aws-elasticloadbalancingv2';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as secretsmanager from 'aws-cdk-lib/aws-secretsmanager';
import * as logs from 'aws-cdk-lib/aws-logs';
import * as cw from 'aws-cdk-lib/aws-cloudwatch';
import * as route53 from 'aws-cdk-lib/aws-route53';
import { Construct } from 'constructs';
import * as path from 'path';
import Mustache = require("mustache");
import fs =  require("fs");
import { InterfaceVpcEndpointTarget } from 'aws-cdk-lib/aws-route53-targets';
import { ZillaPlusStackProps } from '../bin/app';

interface TemplateData {
  name: string;
  vault: string;
  cloudwatch?: object;
  internal?: object;
  external?: object;
}

interface ScalingStep {
  lower?: number;
  upper?: number;
  change: number;
}

interface SecurePublicAccessVpcContext {
  cidr: string
}

interface SecurePublicAccessSubnetsContext {
  public: SecurePublicAccessSubnetContext,
  private: SecurePublicAccessSubnetContext
}

interface SecurePublicAccessSubnetContext {
  cidrMask: number
}

interface SecurePublicAccessInternalContext {
  servers: string,
  trust: string,
  privateLinkServiceId?: string
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
  namespace: string,
  interval: number
}

interface SecurePublicAccessCloudWatchLogsContext {
  group: string,
  stream?: string
}

interface SecurePublicAccessContext {
  vpcId?: string,
  cidrs?: string[],
  peeringConnectionId?: string,
  vpc?: SecurePublicAccessVpcContext,
  subnets?: SecurePublicAccessSubnetsContext,
  internal: SecurePublicAccessInternalContext;
  external: SecurePublicAccessExternalContext;
  cloudwatch?: SecurePublicAccessCloudWatchContext,
  scalingSteps?: ScalingStep[],
  securityGroup?: string,
  roleName?: string,
  capacity?: number,
  instanceType?: string,
  sshKey?: string,
  ami?: string,
  version?: string
}

export class SecurePublicAccessStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props?: ZillaPlusStackProps) {
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
    if (context.cloudwatch && context.cloudwatch.metrics) {
      context.cloudwatch.metrics.interval = props?.interval ?? 20;
    }
    context.version ??= "latest";
    context.capacity ??= props?.freeTrial ? 1 : 2;
    context.instanceType ??= 'c6i.xlarge';
    context.external.trust ??= context.internal.trust;

    const [internalServer, internalPort] = context.internal.servers.split(',')[0].split(':');
    const internalWildcardDNS = `*.${internalServer.split('.').slice(1).join(".")}`;

    const internalPrivateLink = internalWildcardDNS.split(".").includes("private");
    const internalVpcPeering = internalWildcardDNS.split(".").includes("glb");

    const [externalServer, externalPort] = context.external.servers.split(',')[0].split(':');
    const externalWildcardDNS = `*.${externalServer.split('.').slice(1).join(".")}`;

    // zilla.yaml template data
    const zillaYamlData: TemplateData = {
      name: 'public',
      vault: nitroEnclavesEnabled ? 'aws-acm' : 'aws-secrets',
      internal: {},
      external: {}
    };

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
        'Allow inbound traffic on external port');
    }

    if (internalPrivateLink) {
      const vpcEndpoint = vpc.addInterfaceEndpoint(`ZillaPlus-PrivateLinkEndpoint`, {
        service: new ec2.InterfaceVpcEndpointService(context.internal.privateLinkServiceId ?? "", Number(internalPort)),
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
        zoneName: internalServer.split('.').slice(1).join(".")
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
        assumedBy: new iam.ServicePrincipal('ec2.amazonaws.com'),
        managedPolicies: [
          iam.ManagedPolicy.fromAwsManagedPolicyName('AmazonSSMManagedInstanceCore'),
          iam.ManagedPolicy.fromAwsManagedPolicyName('AWSCertificateManagerReadOnly'),
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
          certificateArn: context.external.certificate,
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
            interval: context.cloudwatch.metrics?.interval
          },
        };
      }
    }

    const externalDomain = externalWildcardDNS.split("*.")[1];
    let externalHost;
    let externalDefault;
    let internalHost;
    let internalDefault;
    if (internalPrivateLink) {
      externalHost = `kafka-###.${externalDomain}`;

      const internalServerParts = internalServer.split('.');
      const clusterId = internalServerParts[0];
      internalHost = `${clusterId}-g###.${internalServerParts.slice(1).join(".")}`;

      internalDefault = internalServer.split(':')[0];
    } else if (internalVpcPeering) {
      externalHost = `kafka-#-{rack}.${externalDomain}`;
      externalDefault = `kafka.${externalDomain}`;

      const internalServerParts = internalServer.split('.');
      const clusterIdParts = internalServerParts[0].split('-');

      const firstPart = `lkc-g###-{rack}-${clusterIdParts[2]}`;
      internalHost = `${firstPart}.${internalServerParts.slice(1).join(".")}`;

      internalDefault = internalServer;
    } else {
      externalHost = `b-#.${externalDomain}`;
      internalHost = `b#-${internalServer}`;
    }

    zillaYamlData.external = {
      ...zillaYamlData.external,
      certificate: context.external.certificate,
      trust: context.external.trust,
      authority: externalWildcardDNS,
      host: externalHost,
      defaultHost: externalDefault,
      port: Number(externalPort)
    }

    zillaYamlData.internal = {
      ...zillaYamlData.internal,
      trust: context.internal.trust,
      authority: internalWildcardDNS,
      host: internalHost,
      defaultHost: internalDefault,
      port: Number(internalPort)
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

    const metricsNamespace = context.cloudwatch?.metrics?.namespace ?? 'zilla';

    const metricWorkerUtilization = new cw.Metric({
      namespace: metricsNamespace,
      metricName: 'engine.worker.utilization',
      statistic: 'Average',
      period: cdk.Duration.minutes(5),
    });

    const metricWorkerCount = new cw.Metric({
      namespace: metricsNamespace,
      metricName: 'engine.worker.count',
      statistic: 'Average',
      period: cdk.Duration.minutes(5),
    });

    const metricOverallWorkerUtilization = new cw.MathExpression({
      label: 'OverallWorkerUtilization',
      expression: 'm1 / m2',
      usingMetrics: {
        m1: metricWorkerUtilization,
        m2: metricWorkerCount,
      },
    });

    const scalingSteps = context.scalingSteps ??
    [
      { upper: 0.30, change: -1 },
      { lower: 0.80, change: +2 }
    ]

    autoScalingGroup.scaleOnMetric('WorkerUtilizationStepScaling', {
      metric: metricOverallWorkerUtilization,
      adjustmentType: autoscaling.AdjustmentType.CHANGE_IN_CAPACITY,
      scalingSteps,
      estimatedInstanceWarmup: cdk.Duration.minutes(2),
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
