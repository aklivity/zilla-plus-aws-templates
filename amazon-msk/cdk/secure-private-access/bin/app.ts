#!/usr/bin/env node
import 'source-map-support/register';
import * as cdk from 'aws-cdk-lib';
import { SecurePrivateAccessStack } from '../lib/SecurePrivateAccessStack';
import { SecurePrivateAccessClientStack } from '../lib/SecurePrivateAccessClientStack';
import { MskServerlessClusterStack } from '../lib/MskServerlessClusterStack';

const app = new cdk.App();
const env = {
  account: process.env.CDK_DEFAULT_ACCOUNT,
  region: process.env.CDK_DEFAULT_REGION
};

new MskServerlessClusterStack(app, 'MskServerlessCluster', { env: env });

if (app.node.tryGetContext('SecurePrivateAccess')) {
  new SecurePrivateAccessStack(app, 'SecurePrivateAccess', { env: env });
}

if (app.node.tryGetContext('SecurePrivateAccessClient')) {
  new SecurePrivateAccessClientStack(app, 'SecurePrivateAccessClient', { env: env });
}
