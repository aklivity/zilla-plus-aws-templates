import * as cdk from 'aws-cdk-lib';
import { Construct, Node } from 'constructs';
import * as ec2 from 'aws-cdk-lib/aws-ec2';
import * as iam from 'aws-cdk-lib/aws-iam';
import { aws_logs as logs, aws_elasticloadbalancingv2 as elbv2, aws_autoscaling as autoscaling} from 'aws-cdk-lib';
import Mustache = require("mustache");
import fs =  require("fs");
import { LogGroup, LogStream } from 'aws-cdk-lib/aws-logs';

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

export class ZillaPlusSecurePrivateAccessStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props?: cdk.StackProps) {
    super(scope, id, props);

    function validateRequiredKeys(node: | object, keys: string[]): void {
      const missingKeys = [];
      if (node instanceof Node) {
        missingKeys.push(...keys.filter((key) => !node.tryGetContext(key)));
      } else if (typeof node === 'object' && node !== null) {
        missingKeys.push(...keys.filter((key) => !(key in node)));
      } else {
        throw new Error(`Invalid node type. Must be either a constructs.Node or a JSON object.`);
      }
      if (missingKeys.length > 0) {
        throw new Error(`Missing required context variables: ${missingKeys.join(', ')}`);
      }
    }
    
    // lookup context
    const context = this.node.tryGetContext('zilla-plus');

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
        "acm-pca": new ec2.InterfaceVpcEndpointAwsService("acm-pca"),
        "kms": ec2.InterfaceVpcEndpointAwsService.KMS,
        "s3": ec2.InterfaceVpcEndpointAwsService.S3,
        "iam": ec2.InterfaceVpcEndpointAwsService.IAM
      }
    }

    const vpc = ec2.Vpc.fromLookup(this, 'Vpc', { vpcId: context.vpcId });
    const subnets = vpc.selectSubnets();
    if (subnets.isPendingLookup) {
      // return before using the vpc, the cdk will rerun immediately after the lookup
      return;
    }

    let securityGroups = [];

    if (context.securityGroups) {
      securityGroups = context.securityGroups.map((sgId: string, index: any) =>
        ec2.SecurityGroup.fromLookupById(this, `SecurityGroup-${sgId}`, sgId)
      )
    }
    else {
      const securityGroup = new ec2.SecurityGroup(this, 'SecurityGroup-ZillaPlus', {
        vpc: vpc,
        description: `Zilla Plus Security Group`,
        securityGroupName: `zilla-plus-cdk-${id}`,
      });

      securityGroup.addIngressRule(
        ec2.Peer.anyIpv4(),
        ec2.Port.tcp(context.private.port),
        'Allow inbound traffic on Kafka IAM port');

      securityGroup.addEgressRule(
        ec2.Peer.anyIpv4(),
        ec2.Port.allTcp(),
        'Allow all outbound TCP traffic');

      securityGroups = [securityGroup];
      context.securityGroups = [securityGroup.securityGroupId];
    }

    console.log('securityGroups', securityGroups);

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
          securityGroups: securityGroups
        });
      }
    }

    const [mskServer, mskPort] = context.msk.servers.split(',')[0].split(':');
    const mskWildcardDNS = `*-${mskServer.split('-').slice(1).join("-")}`;

    let zillaPlusRoleName = context.roleName;

    if (!zillaPlusRoleName) {
      const iamRole = new iam.Role(this, `Role-ZillaPlus`, {
        roleName: `zilla-plus-cdk-${id}`,
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

      const iamInstanceProfile = new iam.CfnInstanceProfile(this, `InstanceProfile-ZillaPlus`, {
        instanceProfileName: `zilla-plus-cdk-${id}`,
        roles: [iamRole.roleName],
      });

      const iamPolicy = new iam.PolicyDocument({
        statements: [
          new iam.PolicyStatement({
            sid: 'secretStatement',
            effect: iam.Effect.ALLOW,
            actions: ['secretsmanager:GetSecretValue', 'secretsmanager:DescribeSecret'],
            resources: ['arn:aws:secretsmanager:*:*:secret:*'],
          }),
          new iam.PolicyStatement({
            sid: 'cloudwatchStatement',
            effect: iam.Effect.ALLOW,
            actions: ['logs:*', 'cloudwatch:GenerateQuery', 'cloudwatch:PutMetricData'],
            resources: ['*'],
          }),
        ],
      });

      if (nitroEnclavesEnabled) {
        const association = new ec2.CfnEnclaveCertificateIamRoleAssociation(this, `EnclaveCertificateIamRoleAssociation-ZillaPlus`, {
          certificateArn: context.private.certificate,
          roleArn: iamRole.roleArn,
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

      new iam.CfnPolicy(this, `Policy-ZillaPlus`, {
        policyName: `ZillaPlus-${id}`,
        roles: [iamRole.roleName],
        policyDocument: iamPolicy.toJSON(),
      });

      zillaPlusRoleName = iamInstanceProfile.ref;
    }

    let acmYaml = '';
    let enclavesAcmServiceStart = '';

    if (nitroEnclavesEnabled) {
      acmYaml = `
enclave:
  cpu_count: 2
  memory_mib: 256

options:
  sync_interval_secs: 600

tokens:
  - label: acm-token-example
    source:
      Acm:
        certificate_arn: '${context.private.certificate}'
    refresh_interval_secs: 43200
    pin: 1234
`;
      enclavesAcmServiceStart = `
systemctl enable nitro-enclaves-acm.service
systemctl start nitro-enclaves-acm.service
`;
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

    let imageId =  context.ami;
    if (!imageId) {
      const ami = ec2.MachineImage.lookup({
        name: 'Aklivity Zilla Plus *',
        filters: {
          'product-code': ['ca5mgk85pjtbyuhtfluzisgzy'],
          'is-public': ['true'],
        },
      });
      imageId = ami.getImage(this).imageId;
    }

    const nlb = new elbv2.CfnLoadBalancer(this, `LoadBalancer-ZillaPlus`, {
      name: `zilla-plus-cdk-${id}`,
      scheme: 'internal',
      subnets: context.msk.subnetIds,
      type: 'network',
      ipAddressType: 'ipv4',
    });

    const targetGroup = new elbv2.CfnTargetGroup(this, `TargetGroup-ZillaPlus`, {
      name: `zilla-plus-cdk-${id}`,
      port: context.private.port,
      protocol: 'TCP',
      vpcId: context.vpcId,
    });

    new elbv2.CfnListener(this, `Listener-ZillaPlus`, {
      loadBalancerArn: nlb.ref,
      port: context.private.port,
      protocol: 'TCP',
      defaultActions: [
        {
          type: 'forward',
          targetGroupArn: targetGroup.ref,
        },
      ],
    });

    const externalDomain = context.private.wildcardDNS.split("*.")[1];
    const externalHost = `b-#.${externalDomain}`;

    const internalDomain = mskWildcardDNS.split("*-")[1];
    const internalHost = `b#.${internalDomain}`;
    const defaultInternalHost = `boot-.${internalDomain}`;

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

    const zillaYamlMustache: string = fs.readFileSync('zilla.yaml.mustache', 'utf8');
    const zillaYaml: string = Mustache.render(zillaYamlMustache, zillaYamlData);

    const cfnHupConfContent = `
[main]
stack=${id}
region=${this.region}
    `;

    const cfnAutoReloaderConfContent = `
[cfn-auto-reloader-hook]
triggers=post.update
path=Resources.LaunchTemplate-ZillaPlus.MetaData.AWS::CloudFormation::Init
action=/opt/aws/bin/cfn-init -v --stack ${id} --resource LaunchTemplate-ZillaPlus --region ${this.region}
runas=root
    `;

    const userData = `#!/bin/bash -xe
cat <<EOF > /etc/zilla/zilla.yaml
${zillaYaml}
EOF

cat <<EOF > /etc/nitro_enclaves/acm.yaml
${acmYaml}
EOF

chown ec2-user:ec2-user /etc/zilla/zilla.yaml

mkdir /etc/cfn
cat <<EOF > /etc/cfn/cfn-hup.conf
${cfnHupConfContent}
EOF

chown root:root /etc/cfn/cfn-hup.conf
chmod 0400 /etc/cfn/cfn-hup.conf

mkdir /etc/cfn/hooks.d
cat <<EOF > /etc/cfn/hooks.d/cfn-auto-reloader.conf
${cfnAutoReloaderConfContent}
EOF

chown root:root /etc/cfn/hooks.d/cfn-auto-reloader.conf
chmod 0400 /etc/cfn/hooks.d/cfn-auto-reloader.conf

systemctl enable cfn-hup
systemctl start cfn-hup
systemctl enable amazon-ssm-agent
systemctl start amazon-ssm-agent
${enclavesAcmServiceStart}
systemctl enable zilla-plus
systemctl start zilla-plus

    `;
    
    const launchTemplate = new ec2.CfnLaunchTemplate(this, `LaunchTemplate-ZillaPlus`, {
      launchTemplateData: {
        imageId: imageId,
        instanceType: context.instanceType,
        networkInterfaces: [
          {
            deviceIndex: 0,
            groups: context.securityGroups,
          },
        ],
        iamInstanceProfile: {
          name: zillaPlusRoleName,
        },
        enclaveOptions: {
          enabled: nitroEnclavesEnabled,
        },
        keyName: context.sshKey,
        userData: cdk.Fn.base64(userData)
      },
    });

    console.log('securityGroups', context.securityGroups);

    new autoscaling.CfnAutoScalingGroup(this, `AutoScalingGroup-ZillaPlus`, {
      vpcZoneIdentifier: context.msk.subnetIds,
      launchTemplate: {
        launchTemplateId: launchTemplate.ref,
        version: '1'
      },
      minSize: '1',
      maxSize: '5',
      desiredCapacity: `${context.capacity}`,
      targetGroupArns: [targetGroup.ref]
    });

    const vpceService = new ec2.CfnVPCEndpointService(this, 'VpcEndpointService-ZillaPlus', {
      acceptanceRequired: true,
      networkLoadBalancerArns: [nlb.ref]
    });

    new cdk.CfnOutput(this, 'VpcEndpointServiceId', 
    { 
      description: "ID of the VPC Endpoint Service",
      value: vpceService.ref
    });

    new cdk.CfnOutput(this, 'VpcEndpointServiceName', 
    { 
      description: "Name of the VPC Endpoint Service",
      value: `com.amazonaws.vpce.${this.region}.${vpceService.ref}`
    });
  }
}
