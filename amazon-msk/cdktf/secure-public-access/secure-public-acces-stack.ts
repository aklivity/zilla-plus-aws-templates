import { Construct, Node } from "constructs";
import { TerraformStack, TerraformOutput, Fn, Op } from "cdktf";
import { Lb } from "@cdktf/provider-aws/lib/lb";
import { LbListener } from "@cdktf/provider-aws/lib/lb-listener";
import { autoscalingGroup, dataAwsAmi, launchTemplate } from "@cdktf/provider-aws";
import { LbTargetGroup } from "@cdktf/provider-aws/lib/lb-target-group";
import { DataAwsAcmpcaCertificateAuthority } from "@cdktf/provider-aws/lib/data-aws-acmpca-certificate-authority";
import { DataAwsSecretsmanagerSecretVersion } from "@cdktf/provider-aws/lib/data-aws-secretsmanager-secret-version";
import { CloudwatchLogGroup } from "@cdktf/provider-aws/lib/cloudwatch-log-group";
import { DataAwsMskCluster } from "@cdktf/provider-aws/lib/data-aws-msk-cluster";
import { InternetGateway } from "@cdktf/provider-aws/lib/internet-gateway";
import { Route } from "@cdktf/provider-aws/lib/route";
import { RouteTable } from "@cdktf/provider-aws/lib/route-table";
import { RouteTableAssociation } from "@cdktf/provider-aws/lib/route-table-association";
import { Subnet } from "@cdktf/provider-aws/lib/subnet";
import { IamRole } from "@cdktf/provider-aws/lib/iam-role";
import { IamRolePolicy } from "@cdktf/provider-aws/lib/iam-role-policy";
import { DataAwsMskBrokerNodes } from "@cdktf/provider-aws/lib/data-aws-msk-broker-nodes";
import { DataAwsSubnet } from "@cdktf/provider-aws/lib/data-aws-subnet";
import { DataAwsVpc } from "@cdktf/provider-aws/lib/data-aws-vpc";
import { DataAwsRegion } from "@cdktf/provider-aws/lib/data-aws-region";
import { SecurityGroup } from "@cdktf/provider-aws/lib/security-group";
import { DataAwsAvailabilityZones } from "@cdktf/provider-aws/lib/data-aws-availability-zones";
import { DataAwsSubnets } from "@cdktf/provider-aws/lib/data-aws-subnets";
import { IamInstanceProfile } from "@cdktf/provider-aws/lib/iam-instance-profile";
import { CloudwatchMetricAlarm } from "@cdktf/provider-aws/lib/cloudwatch-metric-alarm";

import { AwsProvider } from "@cdktf/provider-aws/lib/provider";
import { ec2EnclaveCertificateIamRoleAssociation } from "./.gen/providers/awscc"
import { AwsccProvider } from "./.gen/providers/awscc/provider";
import Mustache = require("mustache");
import fs =  require("fs");
import { DataAwsInternetGateway } from "@cdktf/provider-aws/lib/data-aws-internet-gateway";
import { CloudwatchLogStream } from "@cdktf/provider-aws/lib/cloudwatch-log-stream";
import { AutoscalingPolicy } from "@cdktf/provider-aws/lib/autoscaling-policy";

interface TemplateData {
  name: string;
  useAcm: boolean;
  cloudwatch?: object;
  autoscaling: object;
  public?: object;
  mTLS?: boolean;
  externalHost?: string;
  internalHost?: string;
  msk?: object;
}

export class ZillaPlusSecurePublicAccessStack extends TerraformStack {
  constructor(scope: Construct, id: string) {
    super(scope, id);

    const awsProvider = new AwsProvider(this, "AWS", { });
    new AwsccProvider(this, "AWSCC", { });

    const region = new DataAwsRegion(this, "CurrentRegion", {
      provider: awsProvider,
    });

    const mandatoryVariables = [
      'msk',
      'public'
    ];
    
    function validateContextKeys(node: object, keys: string[]): void {
      const missingKeys = [];
      if (node instanceof Node) {
        missingKeys.push(...keys.filter((key) => !node.tryGetContext(key)));
      } else if (typeof node === 'object' && node !== null) {
        missingKeys.push(...keys.filter((key) => !(key in node)));
      }
      if (missingKeys.length > 0) {
        throw new Error(`Missing required context variables: ${missingKeys.join(', ')}`);
      }
    }

    let mskPort;
    let mskWildcardDNS;
    let mskCertificateAuthority;

    const zillaPlusContext = this.node.tryGetContext('zilla-plus');
    validateContextKeys(zillaPlusContext, mandatoryVariables);
    const msk = zillaPlusContext.msk;
    const mandatoryMSKVariables = [
      'cluster',
      'clientAuthentication'
    ];

    zillaPlusContext.autoscaling ??= {};
    zillaPlusContext.autoscaling.cooldown ??= 300;
    zillaPlusContext.autoscaling.warmup ??= 300;
    if (zillaPlusContext.cloudwatch?.metrics) {
      zillaPlusContext.cloudwatch.metrics.interval ??= 30;
    }

    validateContextKeys(msk, mandatoryMSKVariables);
    const mskClusterName = msk.cluster;
    const mskClientAuthentication = msk.clientAuthentication;

    const publicVar = zillaPlusContext.public;
    const mandatoryPublicVariables = [
      'certificate',
      'wildcardDNS'
    ];
    validateContextKeys(publicVar, mandatoryPublicVariables);
    const publicTlsCertificateKey = publicVar.certificate;
    const publicWildcardDNS = publicVar.wildcardDNS;

    const mskCluster = new DataAwsMskCluster(this, "MSKCluster", {
      clusterName: mskClusterName
    });

    const mskClusterBrokerNodes = new DataAwsMskBrokerNodes(this, "MSKClusterBrokerNodes", {
      clusterArn: mskCluster.arn,
    });

    const subnetId = mskClusterBrokerNodes.nodeInfoList.get(0).clientSubnet;

    const subnet = new DataAwsSubnet(this, "Subnet", {
      id: subnetId,
    });

    const vpc = new DataAwsVpc(this, "Vpc", {
      id: subnet.vpcId,
    });

    const subnets = new DataAwsSubnets(this, "PublicSubnets", {
      filter: [
        {
          name: "vpc-id",
          values: [vpc.id],
        },
        {
          name: "mapPublicIpOnLaunch",
          values: ["true"]
        },
      ],
    });

    let igwId = zillaPlusContext.igwId;;
    if (!igwId)
    {
      const igw = new InternetGateway(this, `InternetGateway-${id}`, {
        vpcId: vpc.id,
        tags: {
          Name: "my-igw",
        },
      });
      igwId = igw.id;
    }
    else
    {
      const existingIgw = new DataAwsInternetGateway(this, `ExistingInternetGateway-${id}`, {
        filter: [
          {
            name: "attachment.vpc-id",
            values: [vpc.id],
          },
        ],
      });
      igwId = existingIgw.id;
    }

    const publicRouteTable = new RouteTable(this, `PublicRouteTable-${id}`, {
      vpcId: vpc.id,
      tags: {
        Name: "public-route-table",
      },
    });

    new Route(this, `PublicRoute-${id}`, {
      routeTableId: publicRouteTable.id,
      destinationCidrBlock: "0.0.0.0/0",
      gatewayId: igwId,
    });

    const availabilityZones = new DataAwsAvailabilityZones(this, "AZs", {});
    const subnetOffset = subnets.ids.length;
    const subnetMask = Fn.parseint(Fn.element(Fn.split("/", vpc.cidrBlock), 1), 10);
    const availableIpv4 = subnet.availableIpAddressCount;
    // Math magic to find next power of 2 and based on the subnetAddressPower
    const subnetAddressPower = Fn.log(Fn.pow(2, Fn.ceil(Fn.log(availableIpv4, 2))), 2);
    const subnetsMax = Op.sub(32, Op.add(subnetAddressPower, subnetMask));

    const subnetIds = [];
    for (let i = 1; i < 3; i++) {
      const az = Fn.element(availabilityZones.names, i);
      const subnetIndex = subnetOffset + i;
      const cidrBlock = Fn.cidrsubnet(vpc.cidrBlock, subnetsMax, subnetIndex + i);

      const subnet = new Subnet(this, `PublicSubnet${i}-${id}`, {
        vpcId: vpc.id,
        cidrBlock: cidrBlock,
        availabilityZone: az,
        mapPublicIpOnLaunch: true,
        tags: {
          Name: `public-subnet-${subnetIndex + 1}-${id}`,
        },
      });

      subnetIds.push(subnet.id);

      new RouteTableAssociation(this, `PublicSubnet${i}RouteTableAssociation-${id}`, {
        subnetId: subnet.id,
        routeTableId: publicRouteTable.id,
      });
    }

    const bootstrapServers =
      mskClientAuthentication === "mTLS"
        ? mskCluster.bootstrapBrokersTls
        : mskClientAuthentication === "SASL/SCRAM"
        ? mskCluster.bootstrapBrokersSaslScram
        : mskCluster.bootstrapBrokers;

    const domainParts = Fn.split(":", Fn.element(Fn.split(",", bootstrapServers), 0));
    const serverAddress = Fn.element(domainParts, 0);
    mskPort = Fn.element(domainParts, 1);
    const addressParts = Fn.split(".", serverAddress);
    const mskBootstrapCommonPart = Fn.join(".", Fn.slice(addressParts, 1, Fn.lengthOf(addressParts)));
    mskWildcardDNS = Fn.format("*.%s", [mskBootstrapCommonPart]);

    const mTLSEnabled = mskClientAuthentication === "mTLS";
    const publicTlsCertificateViaAcm: boolean = publicTlsCertificateKey.startsWith("arn:aws:acm");

    const data: TemplateData = {
      name: 'public',
      useAcm: publicTlsCertificateViaAcm,
      mTLS: mTLSEnabled,
      autoscaling: zillaPlusContext.autoscaling,
      public: {}
    };

    if (mTLSEnabled) {
      validateContextKeys(msk, ['certificateAuthorityArn']);
      const mskCertificateAuthorityArn = msk.certificateAuthorityArn;
      const publicCertificateAuthority = publicVar.certificateAuthorityArn ?? mskCertificateAuthorityArn;
      data.msk  = {
        certificateAuthority: mskCertificateAuthorityArn
      }
      // Validate that the PCA exists
      new DataAwsAcmpcaCertificateAuthority(this, "MSKCertificateAuthority", {
        arn: mskCertificateAuthorityArn
      });
      mskCertificateAuthority = mskCertificateAuthority;

      // Validate that the PCA exists
      new DataAwsAcmpcaCertificateAuthority(this, "publicCertificateAuthority", {
        arn: publicCertificateAuthority,
      });
      data.public  = {
        certificateAuthority: publicCertificateAuthority
      }
    }

    let zillaPlusRole = zillaPlusContext.roleName;

    if (!zillaPlusRole) {
      const iamRole = new IamRole(this, `zilla_plus_role-${id}`, {
        name: `zilla_plus_role-${id}`,
        assumeRolePolicy: JSON.stringify({
          Version: "2012-10-17",
          Statement: [
            {
              Effect: "Allow",
              Principal: {
                Service: "ec2.amazonaws.com",
              },
              Action: "sts:AssumeRole",
            },
            {
              Effect: "Allow",
              Principal: {
                Service: "cloudformation.amazonaws.com",
              },
              Action: "sts:AssumeRole",
            },
          ],
        }),
        managedPolicyArns: [
          "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore",
          "arn:aws:iam::aws:policy/AWSCertificateManagerReadOnly",
          "arn:aws:iam::aws:policy/AWSGlueSchemaRegistryReadonlyAccess",
          "arn:aws:iam::aws:policy/CloudWatchLogsFullAccess",
        ],
        inlinePolicy: [
          {
            name: "CCProxySecretsManagerRead",
            policy: JSON.stringify({
              Version: "2012-10-17",
              Statement: [
                {
                  Sid: "VisualEditor0",
                  Effect: "Allow",
                  Action: [
                    "acm-pca:GetCertificate",
                    "acm-pca:GetCertificateAuthorityCertificate",
                    "acm-pca:DescribeCertificateAuthority",
                    "tag:GetResources",
                    "secretsmanager:GetSecretValue",
                    "secretsmanager:DescribeSecret",
                  ],
                  Resource: [
                    "arn:aws:secretsmanager:*:*:secret:wildcard.example.aklivity.io*",
                    "arn:aws:secretsmanager:*:*:secret:client-*",
                    "*",
                  ],
                },
              ],
            }),
          },
        ],
      });

      const iamInstanceProfile = new IamInstanceProfile(this, `zilla_plus_instance_profile-${id}`, {
        name: `zilla_plus_role-${id}`,
        role: iamRole.name,
      });

      const iamPolicy = {
        Version: "2012-10-17",
        Statement: [
          {
            Sid: "secretStatement",
            Effect: "Allow",
            Action: ["secretsmanager:GetSecretValue", "secretsmanager:DescribeSecret"],
            Resource: ["arn:aws:secretsmanager:*:*:secret:*"],
          },
          {
            Sid: "cloudwatchStatement",
            Effect: "Allow",
            Action: ['logs:*', 'cloudwatch:GenerateQuery', 'cloudwatch:PutMetricData'],
            Resource: ["*"],
          },
        ],
      };

      if (publicTlsCertificateViaAcm) {
        iamPolicy.Statement = iamPolicy.Statement.concat([
          {
            "Sid": "s3Statement",
            "Effect": "Allow",
            "Action": [ "s3:GetObject" ],
            "Resource": ["arn:aws:s3:::*/*"]
          },
          {
            "Sid": "kmsDecryptStatement",
            "Effect": "Allow",
            "Action": [ "kms:Decrypt" ],
            "Resource": ["arn:aws:kms:*:*:key/*"]
          },
          {
            "Sid": "getRoleStatement",
            "Effect": "Allow",
            "Action": [ "iam:GetRole" ],
            "Resource": [ `arn:aws:iam::*:role/${iamRole.name}` ]
          }]
        );

        new ec2EnclaveCertificateIamRoleAssociation.Ec2EnclaveCertificateIamRoleAssociation(this, `ZillaPlusEnclaveIamRoleAssociation-${id}`, {
          roleArn: iamRole.arn,
          certificateArn: publicTlsCertificateKey
        });
      }

      new IamRolePolicy(this, `ZillaPlusRolePolicy-${id}`, {
        role: iamRole.name,
        policy: JSON.stringify(iamPolicy),
      });

      zillaPlusRole = iamInstanceProfile.name;
    }

    let zillaPlusSecurityGroups = zillaPlusContext.securityGroups;

    if (zillaPlusSecurityGroups) {
      zillaPlusSecurityGroups = zillaPlusSecurityGroups.split(',');
    } else {
      const zillaPlusSG = new SecurityGroup(this, `ZillaPlusSecurityGroup-${id}`, {
        vpcId: vpc.id,
        description: "Security group for Zilla Plus",
        ingress: [
          {
            fromPort: 9092,
            toPort: 9096,
            protocol: "tcp",
            cidrBlocks: ["0.0.0.0/0"],
          },
        ],
        egress: [
          {
            fromPort: 0,
            toPort: 65535,
            protocol: "tcp",
            cidrBlocks: ["0.0.0.0/0"],
          },
        ],
        tags: {
          Name: "zilla-plus-security-group",
        },
      });
      zillaPlusSecurityGroups = [zillaPlusSG.id];
    }

    const zillaPlusCapacity = zillaPlusContext.capacity ?? 2;
    const publicPort = publicVar.port ?? 9094;

    if (!publicTlsCertificateViaAcm) {
      // Validate that the Certificate Key exists
      new DataAwsSecretsmanagerSecretVersion(this, "publicTlsCertificate", {
        secretId: publicTlsCertificateKey,
      });
    }

    let keyName = zillaPlusContext.sshKey;
    let acmYamlContent = '';
    let enclavesAcmServiceStart = '';

    if (publicTlsCertificateViaAcm) {
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
        certificate_arn: '${publicTlsCertificateKey}'
    refresh_interval_secs: 43200
    pin: 1234
`
      enclavesAcmServiceStart = `
systemctl enable nitro-enclaves-acm.service
systemctl start nitro-enclaves-acm.service
`
    }

    const cloudwatch = zillaPlusContext.cloudwatch;
    const cloudwatchDisabled = cloudwatch?.disabled ?? false;

    if (!cloudwatchDisabled) {
      const defaultLogGroupName = `${id}-group`;
      const defaultMetricNamespace = `${id}-namespace`;

      const logGroupName = cloudwatch?.logs?.group ?? defaultLogGroupName;
      const metricNamespace = cloudwatch?.metrics?.namespace ?? defaultMetricNamespace;

      const cloudWatchLogGroup = new CloudwatchLogGroup(this, `loggroup-${id}`, {
        name: logGroupName
      });

      new CloudwatchLogStream(this, `LogStream-${id}`, {
        logGroupName: cloudWatchLogGroup.name,
        name: 'events'
      });

      data.cloudwatch = {
        logs: {
          group: logGroupName,
        },
        metrics: {
          namespace: metricNamespace,
          interval: cloudwatch?.metrics?.interval
        },
      };
    }

    const defaultInstanceType = publicTlsCertificateViaAcm ? 'c6i.xlarge' : 't3.small';
    const instanceType = zillaPlusContext.instanceType ?? defaultInstanceType;

    let imageId =  zillaPlusContext.ami;
    if (!imageId) {
      const ami = new dataAwsAmi.DataAwsAmi(this, "LatestAmi", {
        mostRecent: true,
        filter: [
          {
            name: "product-code",
            values: ["ca5mgk85pjtbyuhtfluzisgzy"],
          },
          {
            name: "is-public",
            values: ["true"],
          },
        ],
      });
      imageId = ami.imageId;
    }

    const nlb = new Lb(this, `NetworkLoadBalancer-${id}`, {
      name: `nlb-${id}`,
      loadBalancerType: "network",
      internal: false,
      subnets: subnetIds,
      enableCrossZoneLoadBalancing: true,
    });

    const nlbTargetGroup = new LbTargetGroup(this, `NLBTargetGroup-${id}`, {
      name: `nlb-tg-${id}`,
      port: publicPort,
      protocol: "TCP",
      vpcId: vpc.id,
    });

    new LbListener(this, `NLBListener-${id}`, {
      loadBalancerArn: nlb.arn,
      port: publicPort,
      protocol: "TCP",
      defaultAction: [
        {
          type: "forward",
          targetGroupArn: nlbTargetGroup.arn,
        },
      ],
    });

    const externalHost = ["b-#.", publicWildcardDNS.split("*.")[1]].join("");
    const internalHost = ["b-#.", Fn.element(Fn.split("*.", mskWildcardDNS), 1)].join("");

    data.public = {
      ...data.public,
      port: publicPort,
      certificate: publicTlsCertificateKey,
      wildcardDNS: publicWildcardDNS
    }
    data.externalHost = externalHost;
    data.internalHost = internalHost;
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
region=${region}
    `;

    const cfnAutoReloaderConfContent = `
[cfn-auto-reloader-hook]
triggers=post.update
path=Resources.ZillaPlusLaunchTemplate.Metadata.AWS::CloudFormation::Init
action=/opt/aws/bin/cfn-init -v --stack ${id} --resource ZillaPlusLaunchTemplate --region ${region}
runas=root
    `;

    const userData = `#!/bin/bash -xe
yum update -y aws-cfn-bootstrap
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

    const ZillaPlusLaunchTemplate = new launchTemplate.LaunchTemplate(this, `ZillaPlusLaunchTemplate-${id}`, {
      imageId: imageId,
      instanceType: instanceType,
      networkInterfaces: [
        {
          associatePublicIpAddress: "true",
          deviceIndex: 0,
          securityGroups: zillaPlusSecurityGroups,
        },
      ],
      iamInstanceProfile: {
        name: zillaPlusRole,
      },
      enclaveOptions: {
        enabled: publicTlsCertificateViaAcm
      },
      keyName: keyName,
      userData: Fn.base64encode(userData),
    });

    const zillaAutoScalingGroup = new autoscalingGroup.AutoscalingGroup(this, `ZillaPlusGroup-${id}`, {
      vpcZoneIdentifier: subnetIds,
      launchTemplate: {
        id: ZillaPlusLaunchTemplate.id,
      },
      minSize: 1,
      maxSize: 5,
      desiredCapacity: zillaPlusCapacity,
      defaultCooldown: 300,
      targetGroupArns: [nlbTargetGroup.arn],
    });

    if (!cloudwatchDisabled) {
      const metricsNamespace = cloudwatch?.metrics?.namespace ?? `${id}-namespace`;
  
      const scaleOutPolicy = new AutoscalingPolicy(this, `ScaleOutPolicy-${id}`, {
        name: `OverallWorkerUtilizationScaleOut-${id}`,
        adjustmentType: "ChangeInCapacity",
        autoscalingGroupName: zillaAutoScalingGroup.name,
        scalingAdjustment: 2,
        cooldown: zillaPlusContext.autoscaling.cooldown,
        estimatedInstanceWarmup: zillaPlusContext.autoscaling.warmup,
        policyType: "SimpleScaling"
      });
  
      new CloudwatchMetricAlarm(this, `OverallWorkerUtilizationScaleOutAlarm-${id}`, {
        alarmName: `OverallWorkerUtilizationScaleOut-${id}`,
        comparisonOperator: "GreaterThanThreshold",
        evaluationPeriods: 2,
        threshold: 80,
        alarmDescription: "Overall worker utilization exceeded 80%",
        alarmActions: [scaleOutPolicy.arn],
        metricQuery: [
          {
            id: "e1",
            expression: "m1 / m2 * 100",
            label: "Overall Worker Utilization",
            returnData: true
          },
          {
            id: "m1",
            metric: {
              metricName: "engine.worker.utilization",
              namespace: metricsNamespace,
              period: cloudwatch?.metrics?.interval,
              stat: "Average",
              unit: "Count",
              dimensions: {}
            }
          },
          {
            id: "m2",
            metric: {
              metricName: "engine.worker.count",
              namespace: metricsNamespace,
              period: cloudwatch?.metrics?.interval,
              stat: "Average",
              unit: "Count",
              dimensions: {}
            }
          }
        ]
      });
      
      const scaleInPolicy = new AutoscalingPolicy(this, `ScaleInPolicy-${id}`, {
        name: `OverallWorkerUtilizationScaleIn-${id}`,
        adjustmentType: "ChangeInCapacity",
        autoscalingGroupName: zillaAutoScalingGroup.name,
        scalingAdjustment: -1,
        cooldown: zillaPlusContext.autoscaling.cooldown,
        estimatedInstanceWarmup: zillaPlusContext.autoscaling.warmup,
        policyType: "SimpleScaling"
      });
  
      new CloudwatchMetricAlarm(this, `OverallWorkerUtilizationScaleInAlarm-${id}`, {
        alarmName: `OverallWorkerUtilizationScaleIn-${id}`,
        comparisonOperator: "LessThanThreshold",
        evaluationPeriods: 2,
        threshold: 30,
        alarmDescription: "Overall worker utilization dropped below 30%",
        alarmActions: [scaleInPolicy.arn],
        metricQuery: [
          {
            id: "e1",
            expression: "m1 / m2 * 100",
            label: "Overall Worker Utilization (%)",
            returnData: true
          },
          {
            id: "m1",
            metric: {
              metricName: "engine.worker.utilization",
              namespace: metricsNamespace,
              period: cloudwatch?.metrics?.interval,
              stat: "Average",
              unit: "Count",
              dimensions: {}
            }
          },
          {
            id: "m2",
            metric: {
              metricName: "engine.worker.count",
              namespace: metricsNamespace,
              period: cloudwatch?.metrics?.interval,
              stat: "Average",
              unit: "Count",
              dimensions: {}
            }
          }
        ]
      });
    }
  
    new TerraformOutput(this, "NetworkLoadBalancerOutput", {
      description: "Public DNS name of newly created NLB for Zilla Plus",
      value: nlb.dnsName,
    });
  }
}
