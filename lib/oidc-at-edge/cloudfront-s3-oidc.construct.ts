import {
  CacheCookieBehavior,
  CachePolicy,
  CacheQueryStringBehavior,
  Distribution,
  type DistributionProps,
  LambdaEdgeEventType,
  OriginAccessIdentity
} from 'aws-cdk-lib/aws-cloudfront'
import { S3Origin } from 'aws-cdk-lib/aws-cloudfront-origins'
import { Construct } from 'constructs'
import { OIDCAtEdge } from './oidc-at-edge.construct'
import { Bucket } from 'aws-cdk-lib/aws-s3'
import { type SecretValue } from 'aws-cdk-lib'

export class CloudfrontS3OIDC extends Construct {
  distribution: Distribution
  oai: OriginAccessIdentity
  constructor (
    scope: Construct,
    id: string,
    props: {
      bucket?: Bucket
      bucketName?: string
      distribution: Omit<DistributionProps, 'defaultBehavior'>
      oidcConfig: {
        CALLBACK_PATH?: SecretValue | string
        CLIENT_ID?: SecretValue | string
        CLIENT_SECRET?: SecretValue
        DISCOVERY_DOCUMENT?: SecretValue | string
      }
    }

  ) {
    super(scope, id)
    this.oai = new OriginAccessIdentity(
      this,
      'OriginAccessIdentity'
    )

    let bucket = props.bucket
    if (bucket === undefined) {
      bucket = new Bucket(this, 'content-bucket', {
        bucketName: props.bucketName
      })
    }
    bucket.grantRead(this.oai)

    const authFn = new OIDCAtEdge(this, 'oidc-at-edge', {
      name: `${props.bucketName}-oidc`,
      oidcConfig: {
        ...props.oidcConfig,
        DOMAIN: props.distribution.domainNames?.[0]
      }
    })
    this.distribution = new Distribution(this, 'cloudfront-distribution', {
      defaultRootObject: 'index.html',

      ...props.distribution,
      defaultBehavior: {
        origin: new S3Origin(bucket, { originAccessIdentity: this.oai }),
        cachePolicy: new CachePolicy(this, 'CachePolicy', {
          cookieBehavior: CacheCookieBehavior.all(),
          queryStringBehavior: CacheQueryStringBehavior.all()
        }),
        edgeLambdas: [
          {
            functionVersion: authFn.currentVersion,
            eventType: LambdaEdgeEventType.VIEWER_REQUEST
          }
        ]
      }
    })
  }
}
