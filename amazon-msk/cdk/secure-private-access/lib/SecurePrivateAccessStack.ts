import * as cdk from 'aws-cdk-lib';
import { Construct, Node } from 'constructs';
import * as ec2 from 'aws-cdk-lib/aws-ec2';
import * as iam from 'aws-cdk-lib/aws-iam';
import { aws_logs as logs, aws_elasticloadbalancingv2 as elbv2, aws_autoscaling as autoscaling} from 'aws-cdk-lib';
import Mustache = require("mustache");
import fs =  require("fs");
import { LogGroup, LogStream } from 'aws-cdk-lib/aws-logs';
import { validateRequiredKeys } from './validateRequiredKeys';
import { IpAddressType, NetworkListenerAction, TargetType } from 'aws-cdk-lib/aws-elasticloadbalancingv2';

interface TemplateData {
  name: string;
  useAcm: boolean;
  cloudwatch?: object;
  private?: object;
  externalHost?: string;
  internalHost?: string;
  defaultInternalHost?: string;
  msk?: object;
}

export class SecurePrivateAccessStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props?: cdk.StackProps) {
    super(scope, id, props);

    // lookup context
    const context = this.node.getContext(id);

    // validate context
    validateRequiredKeys(context, [ 'vpcId', 'msk', 'private' ]);
    validateRequiredKeys(context.msk, [ 'servers', 'subnetIds' ]);
    validateRequiredKeys(context.private, [ 'certificate', 'wildcardDNS' ]);

    // detect dependencies
    const nitroEnclavesEnabled: boolean = context.private.certificate.startsWith("arn:aws:acm");
    const secretsmanagerEnabled: boolean = context.private.certificate.startsWith("arn:aws:secretsmanager");
    const cloudwatchEnabled: boolean = context?.cloudwatch?.logs?.group || context.cloudwatch?.metrics?.namespace;

    // apply context defaults
    context.private.port ??= 9098;
    context.capacity ??= 2;
    context.instanceType ??= nitroEnclavesEnabled ? 'c6i.xlarge' : 't3.small';
    context.vpceService ??= {}
    context.vpceService.acceptanceRequired ??= true;

    // zilla.yaml template data
    const zillaYamlData: TemplateData = {
      name: 'private',
      useAcm: nitroEnclavesEnabled,
      private: {}
    };

    let endpoints: Record<string, ec2.InterfaceVpcEndpointAwsService> = {
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

    const vpc = ec2.Vpc.fromLookup(this, 'Vpc', { vpcId: context.vpcId });

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
        ec2.Port.tcp(context.private.port),
        'Allow inbound traffic on Kafka IAM port');
    }

    for (const serviceName in endpoints) {
      if (endpoints.hasOwnProperty(serviceName)) {
        if (serviceName == "s3") {
          vpc.addGatewayEndpoint("Endpoint-s3-gateway", {
            service: ec2.GatewayVpcEndpointAwsService.S3,
            subnets: [{ subnetFilters: [ec2.SubnetFilter.byIds(context.msk.subnetIds)] }],
          });
        }

        const service = endpoints[serviceName as keyof typeof endpoints];
        vpc.addInterfaceEndpoint(`Endpoint-${serviceName}`, {
          service: service,
          subnets: { subnetFilters: [ec2.SubnetFilter.byIds(context.msk.subnetIds)] },
          securityGroups: [securityGroup]
        });
      }
    }

    const [mskServer, mskPort] = context.msk.servers.split(',')[0].split(':');
    const mskWildcardDNS = `*-${mskServer.split('-').slice(1).join("-")}`;

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
          certificateArn: context.private.certificate,
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
        const group = LogGroup.fromLogGroupName(this, `LogGroup-$logGroup`, logGroup);
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

    const externalDomain = context.private.wildcardDNS.split("*.")[1];
    const externalHost = `b-#.${externalDomain}`;

    const internalDomain = mskWildcardDNS.split("*-")[1];
    const internalHost = `b#-${internalDomain}`;
    const defaultInternalHost = `boot-${internalDomain}`;

    zillaYamlData.private = {
      ...zillaYamlData.private,
      ...context.private
    }
    zillaYamlData.externalHost = externalHost;
    zillaYamlData.internalHost = internalHost;
    zillaYamlData.defaultInternalHost = defaultInternalHost;
    zillaYamlData.msk = {
      ...zillaYamlData.msk,
      port: mskPort,
      wildcardDNS: mskWildcardDNS
    };

    let userdataData = {
      stack: `${id}`,
      region: `${this.region}`,
      yaml: {}
    }

    if (nitroEnclavesEnabled) {
      const acmYamlData = {
        private: context.private
      }
      const acmYamlMustache: string = fs.readFileSync('acm.yaml.mustache', 'utf8');
      const acmYaml = Mustache.render(acmYamlMustache, acmYamlData);

      userdataData.yaml = {
        ...userdataData.yaml,
        acm: acmYaml
      }
    }

    const zillaYamlMustache: string = fs.readFileSync('zilla.yaml.mustache', 'utf8');
    const zillaYaml: string = Mustache.render(zillaYamlMustache, zillaYamlData);

    userdataData.yaml = {
      ...userdataData.yaml,
      zilla: zillaYaml
    }

    const userdataMustache: string = fs.readFileSync('userdata.mustache', 'utf8');
    const userdata: string = Mustache.render(userdataMustache, userdataData);

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

    // const instanceProfile = new iam.InstanceProfile(this, `ZillaPlus-InstanceProfile`, {
    //   instanceProfileName: `zilla-plus-${id}`,
    //   role: role
    // });

    const keyPair = context.sshKey ? ec2.KeyPair.fromKeyPairName(this, `ZillaPlus-KeyPair`, context.sshKey) : undefined;

    const launchTemplate = new ec2.LaunchTemplate(this, `ZillaPlus-LaunchTemplate`, {
      launchTemplateName: `zilla-plus-${id}`,
      machineImage: machineImage,
      instanceType: new ec2.InstanceType(context.instanceType),
      role: role,
      nitroEnclaveEnabled: nitroEnclavesEnabled,
      securityGroup: securityGroup,
      keyPair: keyPair,
      userData: ec2.UserData.custom(userdata)
    });

    cdk.Tags.of(launchTemplate).add('Name', `ZillaPlus-${id}`);

    const loadBalancer = new elbv2.NetworkLoadBalancer(this, `ZillaPlus-LoadBalancer`, {
      loadBalancerName: `zilla-plus-${id}`,
      internetFacing: false,
      ipAddressType: IpAddressType.IPV4,
      vpc: vpc,
      vpcSubnets: { subnetFilters: [ec2.SubnetFilter.byIds(context.msk.subnetIds)] },
      // securityGroups: [securityGroup],
      // enforceSecurityGroupInboundRulesOnPrivateLinkTraffic: false
    });

    const targetGroup = new elbv2.NetworkTargetGroup(this, `ZillaPlus-TargetGroup`, {
      targetGroupName: `zilla-plus-${id}`,
      protocol: elbv2.Protocol.TCP,
      port: context.private.port,
      vpc: vpc,
      targetType: TargetType.INSTANCE
    });

    loadBalancer.addListener(`TCP-${context.private.port}`, {
      port: context.private.port,
      protocol: elbv2.Protocol.TCP,
      defaultAction: NetworkListenerAction.forward([targetGroup])
    })

    new autoscaling.AutoScalingGroup(this, `ZillaPlus-AutoScalingGroup`, {
      vpc: vpc,
      launchTemplate: launchTemplate,
      minCapacity: context.capacity,
      maxCapacity: 5,
    }).attachToNetworkTargetGroup(targetGroup);

    const vpceService = new ec2.VpcEndpointService(this, 'ZillaPlus-VpcEndpointService', {
      acceptanceRequired: context.vpceService.acceptanceRequired,
      vpcEndpointServiceLoadBalancers: [loadBalancer]
    });

    new cdk.CfnOutput(this, 'VpcEndpointServiceId', 
    { 
      description: "ID of the VPC Endpoint Service",
      value: vpceService.vpcEndpointServiceId
    });

    new cdk.CfnOutput(this, 'VpcEndpointServiceName', 
    { 
      description: "Name of the VPC Endpoint Service",
      value: vpceService.vpcEndpointServiceName
    });
  }
}
