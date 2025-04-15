#!/usr/bin/env node
import 'source-map-support/register';
import * as cdk from 'aws-cdk-lib';
import { SecurePublicAccessStack } from '../lib/SecurePublicAccessStack';
import { IotIngestAndControlStack } from '../lib/IotIngestAndControlStack';


const app = new cdk.App();
const env = {
  account: process.env.CDK_DEFAULT_ACCOUNT,
  region: process.env.CDK_DEFAULT_REGION
};

if (app.node.tryGetContext('IotIngestAndControl')) {
  new IotIngestAndControlStack(app, 'IotIngestAndControl', { env: env });
}

if (app.node.tryGetContext('SecurePublicAccess')) {
  new SecurePublicAccessStack(app, 'SecurePublicAccess', { env: env });
}
