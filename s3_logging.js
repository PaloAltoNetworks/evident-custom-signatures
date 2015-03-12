dsl.configure(function(c){
  c.module      = 's3_logging';
  c.identifier  = 'AWS::ESPS3-001';
  c.description = 'Check S3 buckets for logging';
  c.usage             = 'metascrape.signatures.s3_object_logging_enabled.perform metascrape.customers.evident';
  c.tags              = ['s3', 'signature'];
  c.deep_inspection   = ['bucket', 'bucketName', 'logging'];
  c.unique_identifier = ['bucketName'];
});

function perform(aws) {
  try {
    var buckets = aws.s3.list_buckets().buckets;
    var alerts  = [];

    buckets.map(function(bucket) {
      var bucketName = bucket.name;
      var bucket_log = aws.s3.get_bucket_logging({ bucket: bucketName });
      var report = { bucket: bucket, bucketName: bucketName, logging: bucket_log };
      dsl.set_data(report);

      if (bucket_log.logging_enabled) {
        alerts.push(dsl.pass({resource_id: bucketName, message: "Bucket " + bucketName + " has logging enabled"}))
      } else {
        alerts.push(dsl.fail({resource_id: bucketName, message: "Bucket " + bucketName + " does not have logging enabled"}))
      }
    });

    return alerts
  } catch (err) {
    return dsl.error({ error: err.message });
  }
}
