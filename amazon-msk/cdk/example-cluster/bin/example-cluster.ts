import * as cdk from 'aws-cdk-lib';
import { ZillaPlusExampleMskCluster } from '../lib/example-cluster-stack';

const app = new cdk.App();
new ZillaPlusExampleMskCluster(app, 'ZillaPlusExampleMskCluster', {
  enableMtls: process.env.MTLS_ENABLED === 'true',
  mskCertificateAuthorityArn: process.env.MTLS_ENABLED === 'true' ? process.env.MSK_CERTIFICATE_AUTHORITY_ARN : undefined,
});
