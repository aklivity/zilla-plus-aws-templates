#!/usr/bin/env node
import * as cdk from 'aws-cdk-lib';
import { IotIngestAndControlStack } from '../lib/iot-ingest-and-control-stack';

const app = new cdk.App();
new IotIngestAndControlStack(app, 'IotIngestAndControlStack', {
  env: {
    account: process.env.CDK_DEFAULT_ACCOUNT,
    region: process.env.CDK_DEFAULT_REGION
}});
