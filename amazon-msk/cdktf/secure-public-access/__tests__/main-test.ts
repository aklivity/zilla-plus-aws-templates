import "cdktf/lib/testing/adapters/jest";
import { Testing } from "cdktf";
import { ZillaPlusSecurePublicAccessStack } from "../secure-public-acces-stack";
import { CloudwatchLogGroup } from "@cdktf/provider-aws/lib/cloudwatch-log-group";
import { autoscalingGroup, launchTemplate } from "@cdktf/provider-aws";
import { LbTargetGroup } from "@cdktf/provider-aws/lib/lb-target-group";
import { LbListener } from "@cdktf/provider-aws/lib/lb-listener";
import { Lb } from "@cdktf/provider-aws/lib/lb";

describe("Zilla Plus Public Access Stack Test", () => {
  let output: string;

  beforeAll(() => {
    const app = Testing.app({
      context: {
        "zilla-plus":
        {
          "msk":
          {
            "cluster": "test-cluster",
            "clientAuthentication": "SASL/SCRAM"  
          },
          "public":
          {
            "certificate": "test-certificate",
            "wildcardDNS": "*.example.aklivity.io"
          }
        }
    }});
    const stack = new ZillaPlusSecurePublicAccessStack(app, "test");
    output = Testing.synth(stack);
  });

  it("should have auto scaling group", async () => {
    expect(output).toHaveResourceWithProperties(
      autoscalingGroup.AutoscalingGroup,
      {
        min_size: 1,
        max_size: 5,
        launch_template: expect.objectContaining({
          id: expect.stringContaining(
            "${aws_launch_template.ZillaPlusLaunchTemplate-test.id}"
          ),
        }),
        target_group_arns: expect.arrayContaining([
          "${aws_lb_target_group.NLBTargetGroup-test.arn}",
        ]),
        vpc_zone_identifier: [
          "${aws_subnet.PublicSubnet1-test.id}",
          "${aws_subnet.PublicSubnet2-test.id}",
        ],
      }
    );
  });

  it("should have cloudwatch group resource", async () => {
    expect(output).toHaveResourceWithProperties(CloudwatchLogGroup, {
      name: "test-group",
    });
  });

  it("should have load balancer target group", async () => {
    expect(output).toHaveResourceWithProperties(LbTargetGroup, {
      vpc_id: "${data.aws_vpc.Vpc.id}",
      name: "nlb-tg-test",
      port: 9094,
      protocol: "TCP",
    });
  });

  it("should have load balancer", async () => {
    expect(output).toHaveResourceWithProperties(Lb, {
      enable_cross_zone_load_balancing: true,
      internal: false,
      load_balancer_type: "network",
      name: "nlb-test",
      subnets: [
        "${aws_subnet.PublicSubnet1-test.id}",
        "${aws_subnet.PublicSubnet2-test.id}",
      ],
    });
  });

  it("should have load balancer listener", async () => {
    expect(output).toHaveResourceWithProperties(LbListener, {
      default_action: [
        {
          target_group_arn: "${aws_lb_target_group.NLBTargetGroup-test.arn}",
          type: "forward",
        },
      ],
      load_balancer_arn: "${aws_lb.NetworkLoadBalancer-test.arn}",
      port: 9094,
      protocol: "TCP",
    });
  });

  it("should have launch template", async () => {
    expect(output).toHaveResourceWithProperties(launchTemplate.LaunchTemplate, {
      iam_instance_profile: {
        name: "${aws_iam_instance_profile.zilla_plus_instance_profile-test.name}",
      },
      image_id: "${data.aws_ami.LatestAmi.image_id}",
      instance_type: "t3.small",
      network_interfaces: [
        {
          associate_public_ip_address: "true",
          device_index: 0,
          security_groups: ["${aws_security_group.ZillaPlusSecurityGroup-test.id}"],
        },
      ],
    });
  });
});
