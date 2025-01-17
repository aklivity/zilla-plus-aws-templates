import "cdktf/lib/testing/adapters/jest";
import { Testing } from "cdktf";
import { CloudwatchLogGroup } from "@cdktf/provider-aws/lib/cloudwatch-log-group";
import { autoscalingGroup, launchTemplate } from "@cdktf/provider-aws";
import { LbTargetGroup } from "@cdktf/provider-aws/lib/lb-target-group";
import { LbListener } from "@cdktf/provider-aws/lib/lb-listener";
import { Lb } from "@cdktf/provider-aws/lib/lb";
import { ZillaPlusWebStreamingStack } from "../web-streaming-stack";

describe("Zilla Plus Web Streaming Stack Test", () => {
  let output: string;

  beforeAll(() => {

    const app = Testing.app({
      context: {
        "zilla-plus":
        {
          "msk":
          {
            "cluster": "test-cluster",
            "credentials": "test-credentials"  
          },
          "public":
          {
            "certificate": "test-certificate"
          },
          "mappings": 
          [
            {"topic": "pets"}
          ]
        }
    }});

    const stack = new ZillaPlusWebStreamingStack(app, "test");
    output = Testing.synth(stack);
  });

  it("should have auto scaling group", async () => {
    expect(output).toHaveResourceWithProperties(
      autoscalingGroup.AutoscalingGroup,
      {
        desired_capacity: 2,
        launch_template: {
          id: "${aws_launch_template.ZillaPlusLaunchTemplate-test.id}",
        },
        max_size: 5,
        min_size: 1,
        target_group_arns: ["${aws_lb_target_group.NLBTargetGroup-test.arn}"],
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
    delete process.env.CLOUDWATCH_ENABLED;
  });

  it("should have load balancer target group", async () => {
    expect(output).toHaveResourceWithProperties(LbTargetGroup, {
      name: "nlb-tg-test",
      port: 7143,
      protocol: "TCP",
      vpc_id: "${data.aws_vpc.Vpc.id}",
    });
  });

  it("should have load balancer", async () => {
    expect(output).toHaveResourceWithProperties(Lb, {
      enable_cross_zone_load_balancing: true,
      internal: false,
      load_balancer_type: "network",
      name: "nlb-test",
      security_groups: ["${aws_security_group.ZillaPlusSecurityGroup-test.id}"],
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
      port: 7143,
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
