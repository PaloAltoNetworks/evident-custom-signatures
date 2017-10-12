# Custom Signatures

This is a repo of custom signature samples that you can use in your environment.

Source code files are provided for demonstration purposes only.

Please email support@evident.io if you have any questions.

# Custom Signature Tutorial ( javascript )

## `overview`
A custom signature is a function that reads [AWS SDK](http://docs.aws.amazon.com/sdkforruby/api/) data from Amazon, and creates one or more __alerts__ based on that data and conditionals you describe.  

An __alert__ has
* a status of `pass` `fail` `warn` or `error`
* identifying metadata such as `instance_id` or `logging_status`
* This field is used to identify unique alerts that share the same signature but describe different AWS resources (ex. `volume_id` `instance_id` `bucket_name`)

* * *

A custom signature will always have two sections `config` and `perform`.  

In the `config` section you define the parameters your signature will use when it runs. For example, you set which region you are interested in checking, and you give the signature a unique id.

In the `perform` section you write a function that implements your security policy, and creates one or more __alerts__.  The alerts are themselves are created using the `dsl.pass()` and `dsl.fail()` functions. Take those objects returned by the functions and push them onto an array of __alerts__. When you are done return them at the end of the `perform` block.  Each __alert__ is then stored in the database.

## `config`

An example `config` section
```javascript
dsl.configure(function(c) {
  c.valid_regions = ['us_east_1'];
  c.identifier = 'AWS:EC2-909'
  c.deep_inspection = ['volume_type', 'volume_id'];
  c.unique_identifier = ['volume_id'];
});
```
`dsl.configure` is a function that is passed an anonymous callback function that receives a configuration object (here `c`) as the first argument.  Inside the anonymous function you have access the configuration settings for the signature.


#### configuration metadata

##### `valid_regions`
* An array of regions to run the signature
* ex. `['us_east_1', 'us_west_2']`

##### `identifier`
* A unique string identifying the signature in the database. Usually takes the
form `AWS:SERVICE_CODE-SOME_NUMBER`
* ex. `AWS:EC2-303` or `AWS:R52:909`

##### `deep_inspection`
* An array of fields that provide additional information beyond the status when
an alert is viewed in the actual report.  
* These fields are referenced in the `perform` block when you call
`dsl.set_data()`

##### `unique_identifier`
* An array of fields that are used to identify the alert as unique in the
 database.
* This is commonly unique to the resource being described in the alert.

## `perform`

The `perform` section is a function that is passed the
 [AWS SDK](http://docs.aws.amazon.com/sdkforruby/api/) as an object.  You use
this `aws` object to make calls to AWS.  

Perform block psuedocode looks like
```javascript
function perform(aws){
  try {

    // make a container for returned alerts
    var alerts = []

    // make some AWS calls to get an array of resources
    //
    // for each resource
    // {
    //    read some resource information using the aws object passed to the
    //    perform function
    //
    //    store some of that resource information to the report using
    //    dsl.set_data()
    //
    //    compare it to a desired value or state
    //      push a dsl.pass() or dsl.fail() to the alerts container
    //        ex. alerts.push(dsl.fail({message:'failed'}))
    // }
    //

    return alerts;

  } catch(err){
    return dsl.error({
      errors: err.message
    })
  }
}
```



An example `perform` section:
```javascript

function perform(aws) {
  try {

    // make the container for returned alerts
    var alerts = [];

    var region = aws.region;

    // these are AWS SDK calls to get a list of resources to check
    var volumes = aws.ec2.describe_volumes().volumes;

    // this is our condition we are searching for in this signature
    // we want to enforce a specific volume type in this region
    // if you change the variable below to 'gp2' it will use that
    var type_to_check_for = 'standard'


    // for each volume returned from the AWS SDK call
    volumes.map(function(volume) {

      // this is where you specify the data for the fields listed in the
      // deep_inspection array
      // create an object and give it some information
      var report = {
        volume_type: volume.volume_type,
        volume_id: volume.volume_id
      };

      // call dsl.set_data() with that object as the argument and the alert
      // will now have this additional information associated with it
      dsl.set_data(report);

      // our condition check
      // is the volume.volume_type not the same as our desired type?
      if (volume.volume_type !== type_to_check_for) {

        // in this block the volume.volume_type !== type_to_check_for
        // You will create a failed alert with a message.
        // The message is a string, and the failed alert is created by calling
        // dsl.fail({ message: 'some message indicating why'})
        // You then push that object on to the alerts array and the next
        // volume is checked

        var fail_message = 'volume with id '
        fail_message += volume.volume_id + ' is of type '
        fail_message += volume.volume_type + ' and not of type '
        fail_message += type_to_check_for;

        // add the alert to the array of alerts
        alerts.push(dsl.fail({
          message: fail_message
        }));

      } else {

        // in this block the volume.volume_type === type_to_check_for
        // You will create a pass alert with a message.

        var pass_message = 'volume with id ' + volume.volume_id
        pass_message += ' is of type ' + volume.volume_type;

        // add the alert to the array of alerts
        alerts.push(dsl.pass({
          message: pass_message
        }));

      }

    })

    // return the array of alerts
    return alerts;

  } catch (err) {
    return dsl.error({
      errors: err.message
    });
  }
}
```

# Supported Services

When calling AWS methods and classes within Custom Signatures, please use the list below as a reference.

| Class Name | Method Name |
|------------|-------------|
| ACM | acm |
| APIGateway | api_gateway |
| ApplicationAutoScaling | aas |
| ApplicationDiscoveryService | app_discovery_service |
| AppStream | appstream |
| AutoScaling | as |
| Batch | batch |
| Budgets | budgets |
| CloudDirectory | clouddirectory |
| CloudFormation | cfm |
| CloudFront | cf |
| CloudHSM | cloudhsm |
| CloudSearch | cs |
| CloudTrail | ct |
| CloudWatch | cw |
| CloudWatchEvents | cw_events |
| CloudWatchLogs | cwl |
| CodeBuild | code_build |
| CodeCommit | code_commit |
| CodeDeploy | cd |
| CodePipeline | code_pipeline |
| CodeStar | code_star |
| CognitoIdentity | cognito |
| CognitoIdentityProvider | cognito_identity_provider |
| CognitoSync | cognito_sync |
| ConfigService | config |
| CostandUsageReportService | cost_and_usage |
| DatabaseMigrationService | database_migration_service |
| DataPipeline | dp |
| DeviceFarm | device_farm |
| DirectConnect | dc |
| DirectoryService | directory_service |
| DynamoDB | dynamodb |
| DynamoDBStreams | dynamodbstreams |
| EC2 | ec2 |
| ECR | ecr |
| ECS | ecs |
| EFS | elastic_filesystem |
| ElastiCache | ec |
| ElasticBeanstalk | elbs |
| ElasticLoadBalancing | elb |
| ElasticLoadBalancingV2 | elbv2 |
| ElasticsearchService | elastic_search |
| ElasticTranscoder | elt |
| EMR | emr |
| Firehose | firehose |
| GameLift | gamelift |
| Glacier | glacier |
| Health | health |
| IAM | iam |
| ImportExport | ie |
| Inspector | inspector |
| IoT | iot |
| Kinesis | ks |
| KinesisAnalytics | kinesis_analytics |
| KMS | kms |
| Lambda | lambda |
| LambdaPreview | lambda_preview |
| Lex | lex |
| LexModelBuildingService | lex_model_building_service |
| Lightsail | lightsail |
| MachineLearning | machine_learning |
| MarketplaceCommerceAnalytics | market_place |
| MarketplaceMetering | marketplance_metering |
| MTurk | mturk |
| OpsWorks | ops |
| OpsWorksCM | ops_works_cm |
| Organizations | organizations |
| Pinpoint | pinpoint |
| Polly | polly |
| RDS | rds |
| Redshift | rs |
| Rekognition | rekognition |
| ResourceGroupsTaggingAPI | resource_groups_tagging |
| Route53 | route53 |
| Route53Domains | route53_domains |
| S3 | s3 |
| ServiceCatalog | service_catalog |
| SES | ses |
| Shield | shield |
| SimpleDB | sdb |
| SMS | sms |
| Snowball | snowball |
| SNS | sns |
| SQS | sqs |
| SSM | ssm |
| States | states |
| StorageGateway | sg |
| STS | sts |
| Support | support |
| SWF | swf |
| WAF | waf |
| WAFRegional | waf_regional |
| WorkDocs | workdocs |
| WorkSpaces | workspaces |
| XRay | xray |

