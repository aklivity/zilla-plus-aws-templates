import * as dotenvx from "@dotenvx/dotenvx";
import { Construct } from "constructs";

export class UserVariables extends Construct {
  mskClientAuthentication: "mTLS" | "SASL/SCRAM" | "Unauthorized" | "Unknown";
  publicCertificateAuthority: boolean = false;
  createZillaPlusRole: boolean = false;
  createZillaPlusSecurityGroup: boolean = false;
  sshKeyEnabled: boolean = false;
  cloudwatchDisabled: boolean = false;

  constructor(scope: Construct, name: string) {
    super(scope, name);
    dotenvx.config({ quiet: true });
    
    switch ((process.env.MSK_ACCESS_METHOD || "Unknown").toLocaleLowerCase()) {
      case "mTLS".toLocaleLowerCase():
        this.mskClientAuthentication = "mTLS";
        break;
      case "SASL/SCRAM".toLocaleLowerCase():
        this.mskClientAuthentication = "SASL/SCRAM";
        break;
      case "Unauthorized".toLocaleLowerCase():
        this.mskClientAuthentication = "Unauthorized";
        break;
      default:
        this.mskClientAuthentication = "Unknown";
    }
    this.publicCertificateAuthority =
      process.env.PUBLIC_CERTIFICATE_AUTHORITY === "true";
    this.createZillaPlusRole = process.env.CREATE_ZILLA_PLUS_ROLE !== "false";
    this.createZillaPlusSecurityGroup =
      process.env.CREATE_ZILLA_PLUS_SECURITY_GROUP !== "false";
    this.sshKeyEnabled = process.env.SSH_KEY_ENABLED === "true";
    this.cloudwatchDisabled = process.env.CLOUDWATCH_DISABLED === "true";
  }
}
