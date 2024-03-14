/* eslint-disable no-new */

import { ARecord, HostedZone, RecordTarget } from 'aws-cdk-lib/aws-route53'
import { type Construct } from 'constructs'
import {
  Certificate,
  CertificateValidation
} from 'aws-cdk-lib/aws-certificatemanager'
import { CloudFrontTarget } from 'aws-cdk-lib/aws-route53-targets'
import { OAuthScope, UserPool } from 'aws-cdk-lib/aws-cognito'
import { Bucket } from 'aws-cdk-lib/aws-s3'
import { CloudfrontS3OIDC } from '../../lib/oidc-at-edge/cloudfront-s3-oidc.construct'
import { SecretValue, Stack, type StackProps } from 'aws-cdk-lib'

export class CloudfrontOidcCognitoStack extends Stack {
  constructor (
    scope: Construct,
    id: string,
    props: StackProps & {
      appName: string
      hostedZoneId: string
      hostedZoneDomain: string
    }
  ) {
    super(scope, id, { ...props, crossRegionReferences: true })

    const appDomain = `${props.appName}.${props.hostedZoneDomain}`

    const pool = new UserPool(this, 'user-pool', { userPoolName: props.appName })
    pool.addDomain('cognito-domain', {
      cognitoDomain: { domainPrefix: 'cloudfront-oidc-test' }
    })
    const client = pool.addClient('test-client', {
      oAuth: {
        flows: {
          authorizationCodeGrant: true
        },
        scopes: [OAuthScope.OPENID],
        callbackUrls: [`https://${appDomain}/_callback`]
      },
      generateSecret: true
    })

    const publicZone = HostedZone.fromHostedZoneAttributes(
      this,
      `${props.appName}-zone`,
      {
        hostedZoneId: props.hostedZoneId,
        zoneName: props.hostedZoneDomain
      }
    )

    const certificateStack = new Stack(
      this,
      `${props.appName}-certificate-stack`,
      {
        env: {
          region: 'us-east-1'
        },
        crossRegionReferences: true
      }
    )

    const certificate = new Certificate(
      certificateStack,
      `${props.appName}-certificate`,
      {
        domainName: appDomain,
        validation: CertificateValidation.fromDns(publicZone)
      }
    )

    const bucket = new Bucket(this, `${props.appName}-bucket`, {
      bucketName: appDomain
    })
    const cloudfrontOidc = new CloudfrontS3OIDC(this, 'distribution', {
      bucket,
      distribution: {
        domainNames: [appDomain],
        certificate
      },
      oidcConfig: {
        CALLBACK_PATH: '/_callback',
        CLIENT_ID: client.userPoolClientId,
        CLIENT_SECRET: client.userPoolClientSecret,
        DISCOVERY_DOCUMENT: `https://cognito-idp.${this.region}.amazonaws.com/${pool.userPoolId}/.well-known/openid-configuration`
      }
    })

    new ARecord(this, `${props.appName}-dnsrecord`, {
      recordName: props.appName,
      zone: publicZone,
      target: RecordTarget.fromAlias(
        new CloudFrontTarget(cloudfrontOidc.distribution)
      )
    })
  }
}
