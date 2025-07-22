#!/usr/bin/env node
import 'source-map-support/register';
import * as cdk from 'aws-cdk-lib';
import { SecurePublicAccessStack } from '../lib/SecurePublicAccessStack';
import { IotIngestAndControlStack } from '../lib/IotIngestAndControlStack';
import { WebStreamingStack } from '../lib/WebStreamingStack';
import { MarketplaceAgreementClient, GetAgreementTermsCommand, SearchAgreementsCommand } from "@aws-sdk/client-marketplace-agreement";
import { StackProps } from 'aws-cdk-lib';


const app = new cdk.App();
const env = {
  account: process.env.CDK_DEFAULT_ACCOUNT,
  region: process.env.CDK_DEFAULT_REGION
};


export interface ZillaPlusStackProps extends StackProps {
  freeTrial: boolean;
  interval?: number;
}

main();

async function main() {

  let freeTrial = await checkFreeTrial();

  if (app.node.tryGetContext('SecurePublicAccess')) {
    new SecurePublicAccessStack(app, 'SecurePublicAccess', { env: env, freeTrial: freeTrial });
  }

  if (app.node.tryGetContext('IotIngestAndControl')) {
    new IotIngestAndControlStack(app, 'IotIngestAndControl', { env: env, freeTrial: freeTrial });
  }

  if (app.node.tryGetContext('WebStreaming')) {
    new WebStreamingStack(app, 'WebStreaming', { env: env, freeTrial: freeTrial });
  }

  async function checkFreeTrial(): Promise<boolean> {
    const client = new MarketplaceAgreementClient({ region: "us-east-1" });

    const searchCommand = new SearchAgreementsCommand({
      catalog: "AWSMarketplace",
      filters: [
        { name: "PartyType", values: ["Acceptor"] },
        { name: "AgreementType", values: ["PurchaseAgreement"] },
        { name: "ResourceIdentifier", values: ["6ce8dedb-099f-42c5-9c3a-445ba0ccc748"] },
      ],
    });

    try {
      const response = await client.send(searchCommand);
      if (response.agreementViewSummaries && response.agreementViewSummaries.length > 0) {
        const agreementId = response.agreementViewSummaries[0].agreementId;
        const command = new GetAgreementTermsCommand({ agreementId });
        const termsResponse = await client.send(command);

        const terms = termsResponse.acceptedTerms || [];
        return terms.some(term => term.freeTrialPricingTerm?.duration);
      } else {
        return false;
      }
    } catch (error) {
      console.error("Error fetching agreements:", error);
      return false;
    }
  }
}
