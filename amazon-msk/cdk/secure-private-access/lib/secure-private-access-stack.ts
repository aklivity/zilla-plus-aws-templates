import * as cdk from 'aws-cdk-lib';
import { Construct, Node } from 'constructs';
import * as ec2 from 'aws-cdk-lib/aws-ec2';
import * as iam from 'aws-cdk-lib/aws-iam';
import { aws_logs as logs, aws_elasticloadbalancingv2 as elbv2, aws_autoscaling as autoscaling} from 'aws-cdk-lib';
import Mustache = require("mustache");
import fs =  require("fs");


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

    const mandatoryVariables = [
      'vpcId',
      'msk',
      'private'
    ];
    
    function validateContextKeys(node:  | object, keys: string[]): void {
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
    
    const zillaPlusContext = this.node.tryGetContext('zilla-plus');
    validateContextKeys(zillaPlusContext, mandatoryVariables);

    const vpcId = zillaPlusContext.vpcId;
    const msk = zillaPlusContext.msk;
    const mandatoryMSKVariables = [
      'servers',
      'subnetIds'
    ];
    validateContextKeys(msk, mandatoryMSKVariables);
    const subnetIds = msk.subnetIds;


    const privateVar = zillaPlusContext.private;
    const mandatoryPrivateVariables = [
      'certificate',
      'wildcardDNS'
    ];
    validateContextKeys(privateVar, mandatoryPrivateVariables);
    const privateTlsCertificateKey = privateVar.certificate;
    const privateWildcardDNS = privateVar.wildcardDNS;
    const privatePort = privateVar.port ?? 9098;

    const vpc = ec2.Vpc.fromLookup(this, 'Vpc', { vpcId: vpcId });
    const subnets = vpc.selectSubnets();
    if (subnets.isPendingLookup) {
      // return before using the vpc, the cdk will rerun immediately after the lookup
      return;
    }

    let zillaPlusSecurityGroups = zillaPlusContext.securityGroups;
    let zillaPlusSG;
    if (zillaPlusSecurityGroups) {
      zillaPlusSG = zillaPlusSecurityGroups.map((sgId: string, index: any) =>
        ec2.SecurityGroup.fromSecurityGroupId(this, `SecurityGroup${index}`, sgId)
      );
      zillaPlusSecurityGroups = zillaPlusSecurityGroups.split(',');
    } else {
      zillaPlusSG = new ec2.SecurityGroup(this, `ZillaPlusSecurityGroup-${id}`, {
        vpc: vpc,
        description: 'Security group for Zilla Plus',
        securityGroupName: `zilla-plus-security-group-${id}`,
      });

      zillaPlusSG.addIngressRule(ec2.Peer.anyIpv4(), ec2.Port.tcp(privatePort), 'Allow inbound traffic on Kafka IAM port');
      zillaPlusSG.addEgressRule(ec2.Peer.anyIpv4(), ec2.Port.allTcp(), 'Allow all outbound TCP traffic');

      zillaPlusSecurityGroups = [zillaPlusSG.securityGroupId];
    }

    const privateTlsCertificateViaAcm: boolean = privateTlsCertificateKey.startsWith("arn:aws:acm");

    let services: Record<string, ec2.InterfaceVpcEndpointAwsService> = {
      "ssm": ec2.InterfaceVpcEndpointAwsService.SSM,
      "secretsmanager": ec2.InterfaceVpcEndpointAwsService.SECRETS_MANAGER,
      "monitoring": ec2.InterfaceVpcEndpointAwsService.CLOUDWATCH_MONITORING,
      "cloudwatch": ec2.InterfaceVpcEndpointAwsService.CLOUDWATCH_LOGS,
      "cloudformation": ec2.InterfaceVpcEndpointAwsService.CLOUDFORMATION,
      "ssm_messages": ec2.InterfaceVpcEndpointAwsService.SSM_MESSAGES,
      "ec2_messages": ec2.InterfaceVpcEndpointAwsService.EC2_MESSAGES,
    };
    
    if (privateTlsCertificateViaAcm) {
      vpc.addGatewayEndpoint("S3GatewayEndpoint", {
        service: ec2.GatewayVpcEndpointAwsService.S3,
        subnets: [{ subnetFilters: [ec2.SubnetFilter.byIds(subnetIds)] }],
      });

      services = {
        ...services,
        "acm-pca": new ec2.InterfaceVpcEndpointAwsService("acm-pca"),
        "kms": ec2.InterfaceVpcEndpointAwsService.KMS,
        "s3": ec2.InterfaceVpcEndpointAwsService.S3,
        "iam": ec2.InterfaceVpcEndpointAwsService.IAM
      }
    }

    for (const serviceKey in services) {
      if (services.hasOwnProperty(serviceKey)) {
        const service = services[serviceKey as keyof typeof services];
    
        vpc.addInterfaceEndpoint(`Endpoint-${serviceKey}`, {
          service: service,
          subnets: { subnetFilters: [ec2.SubnetFilter.byIds(subnetIds)] },
          securityGroups: [zillaPlusSG]
        });
      }
    }

    const mskBootstrapServers = msk.servers;

    const domainParts = mskBootstrapServers.split(',')[0].split(':');
    const serverAddress = domainParts[0];
    const mskPort = domainParts[1];

    const addressParts = serverAddress.split('-');
    const mskBootstrapCommonPart = addressParts.slice(1).join("-");
    const mskWildcardDNS = `*-${mskBootstrapCommonPart}`;


    const data: TemplateData = {
      name: 'private',
      useAcm: privateTlsCertificateViaAcm,
      private: {}
    };

    let zillaPlusRole = zillaPlusContext.roleName;

    if (!zillaPlusRole) {
      const iamRole = new iam.Role(this, `ZillaPlusRole-${id}`, {
        roleName: `zilla_plus_role-${id}`,
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

      const iamInstanceProfile = new iam.CfnInstanceProfile(this, `ZillaPlusInstanceProfile-${id}`, {
        instanceProfileName: `zilla_plus_role-${id}`,
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

      if (privateTlsCertificateViaAcm) {
        const association = new ec2.CfnEnclaveCertificateIamRoleAssociation(this, `ZillaPlusEnclaveIamRoleAssociation-${id}`, {
          certificateArn: privateTlsCertificateKey,
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

      new iam.CfnPolicy(this, `ZillaPlusRolePolicy-${id}`, {
        policyName: `ZillaPlusRolePolicy-${id}`,
        roles: [iamRole.roleName],
        policyDocument: iamPolicy.toJSON(),
      });

      zillaPlusRole = iamInstanceProfile.ref;
    }

    const zillaPlusCapacity = zillaPlusContext.capacity ?? 2;

    let keyName = zillaPlusContext.sshKey;
    let acmYamlContent = '';
    let enclavesAcmServiceStart = '';

    if (privateTlsCertificateViaAcm) {
      acmYamlContent = `
enclave:
  cpu_count: 2
  memory_mib: 256

options:
  sync_interval_secs: 600

tokens:
  - label: acm-token-example
    source:
      Acm:
        certificate_arn: '${privateTlsCertificateKey}'
    refresh_interval_secs: 43200
    pin: 1234
`;
      enclavesAcmServiceStart = `
systemctl enable nitro-enclaves-acm.service
systemctl start nitro-enclaves-acm.service
`;
    }

    const cloudwatch = zillaPlusContext.cloudwatch;
    const cloudwatchDisabled = cloudwatch?.disabled ?? false;

    if (!cloudwatchDisabled) {
      const defaultLogGroupName = `${id}-group`;
      const defaultMetricNamespace = `${id}-namespace`;

      const logGroupName = cloudwatch?.logs?.group ?? defaultLogGroupName;
      const metricNamespace = cloudwatch?.metrics?.namespace ?? defaultMetricNamespace;

      const cloudWatchLogGroup = new logs.LogGroup(this, `LogGroup-${id}`, {
        logGroupName: logGroupName,
        retention: logs.RetentionDays.ONE_MONTH,
      });

      new logs.LogStream(this, `LogStream-${id}`, {
        logGroup: cloudWatchLogGroup,
        logStreamName: 'events',
      });

      data.cloudwatch = {
        logs: {
          group: cloudWatchLogGroup.logGroupName,
        },
        metrics: {
          namespace: metricNamespace,
        },
      };
    }

    const defaultInstanceType = privateTlsCertificateViaAcm ? 'c6i.xlarge' : 't3.small';
    const instanceType = zillaPlusContext.instanceType ?? defaultInstanceType;

    let imageId =  zillaPlusContext.ami;
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

    const nlb = new elbv2.CfnLoadBalancer(this, `NetworkLoadBalancer-${id}`, {
      name: `nlb-${id}`,
      scheme: 'internal',
      subnets: subnetIds,
      type: 'network',
      ipAddressType: 'ipv4',
    });

    const nlbTargetGroup = new elbv2.CfnTargetGroup(this, `NLBTargetGroup-${id}`, {
      name: `nlb-tg-${id}`,
      port: privatePort,
      protocol: 'TCP',
      vpcId: vpcId,
    });

    new elbv2.CfnListener(this, `NLBListener-${id}`, {
      loadBalancerArn: nlb.ref,
      port: privatePort,
      protocol: 'TCP',
      defaultActions: [
        {
          type: 'forward',
          targetGroupArn: nlbTargetGroup.ref,
        },
      ],
    });

    const externalHost = ["b-#.", privateWildcardDNS.split("*.")[1]].join("");
    const internalHost = ["b#-", mskWildcardDNS.split("*-")[1]].join("");    
    const defaultInternalHost = ["boot-", mskWildcardDNS.split("*-")[1]].join("");



    data.private = {
      ...data.private,
      port: privatePort,
      certificate: privateTlsCertificateKey,
      wildcardDNS: privateWildcardDNS
    }
    data.externalHost = externalHost;
    data.internalHost = internalHost;
    data.defaultInternalHost = defaultInternalHost;
    data.msk = {
      ...data.msk,
      port: mskPort,
      wildcardDNS: mskWildcardDNS
    };

    const yamlTemplate: string = fs.readFileSync('zilla.yaml.mustache', 'utf8');
    const renderedYaml: string = Mustache.render(yamlTemplate, data);

    const cfnHupConfContent = `
[main]
stack=${id}
region=${this.region}
    `;

    const cfnAutoReloaderConfContent = `
[cfn-auto-reloader-hook]
triggers=post.update
path=Resources.ZillaPlusLaunchTemplate.Metadata.AWS::CloudFormation::Init
action=/opt/aws/bin/cfn-init -v --stack ${id} --resource ZillaPlusLaunchTemplate --region ${this.region}
runas=root
    `;

    const userData = `#!/bin/bash -xe
cat <<EOF > /etc/zilla/zilla.yaml
${renderedYaml}
EOF

cat <<EOF > /etc/nitro_enclaves/acm.yaml
${acmYamlContent}
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
    
    const zillaPlusLaunchTemplate = new ec2.CfnLaunchTemplate(this, `ZillaPlusLaunchTemplate-${id}`, {
      launchTemplateData: {
        imageId: imageId,
        instanceType: instanceType,
        networkInterfaces: [
          {
            associatePublicIpAddress: true,
            deviceIndex: 0,
            groups: zillaPlusSecurityGroups,
          },
        ],
        iamInstanceProfile: {
          name: zillaPlusRole,
        },
        enclaveOptions: {
          enabled: privateTlsCertificateViaAcm,
        },
        keyName: keyName,
        userData: cdk.Fn.base64(userData)
      },
    });

    new autoscaling.CfnAutoScalingGroup(this, `ZillaPlusGroup-${id}`, {
      vpcZoneIdentifier: subnetIds,
      launchTemplate: {
        launchTemplateId: zillaPlusLaunchTemplate.ref,
        version: '1'
      },
      minSize: '1',
      maxSize: '5',
      desiredCapacity: zillaPlusCapacity.toString(),
      targetGroupArns: [nlbTargetGroup.ref]
    });

    const vpcEndpointService = new ec2.CfnVPCEndpointService(this, 'VpcEndpointService', {
      acceptanceRequired: true,
      networkLoadBalancerArns: [nlb.ref]
    });

    new cdk.CfnOutput(this, 'VpcEndpointServiceId', 
    { 
      description: "ID of the VPC Endpoint Service",
      value: vpcEndpointService.ref
    });

    new cdk.CfnOutput(this, 'VpcEndpointServiceName', 
    { 
      description: "Name of the VPC Endpoint Service",
      value: `com.amazonaws.vpce.${this.region}.${vpcEndpointService.ref}`
    });
  }
}
