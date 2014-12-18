//
// ec2_golden_ami.js - John Martinez (john@evident.io)
// PROVIDED AS IS WITH NO WARRANTY OR GUARANTEES
//
dsl.configure(function(c){
  c.module      = 'ec2_golden_ami';
  c.identifier  = 'AWS::ESP-EC2-001';
  c.description = 'Check for instances not running the golden AMI ID';
  c.usage             = 'metascrape.signatures.ec2_golden_ami.perform metascrape.customers.evident';
  c.tags              = ['ec2', 'signature'];
  c.deep_inspection   = ['instance_id', 'actual_ami', 'golden_ami'];
  c.unique_identifier = ['instance_id'];
});

function perform(aws) {
  try {
    var alerts  = [];
    var reservations = aws.ec2.describe_instances().reservations;
    var region = aws.region;
    
    reservations.map(function(reservation) {
        var reservationId = reservation.reservation_id;
        var instances = reservation.instances;

        instances.map(function(instance) {
            var instanceId = instance.instance_id;
            var imageId = instance.image_id;
            var goldenImageId = { 
                "us_east_1": "ami-8c1fece5",
                "us_west_2": "ami-22222222"
            };

            var report = { instance_id: instanceId, actual_ami: imageId, golden_ami: goldenImageId};
            dsl.set_data(report);
            
            if (imageId == goldenImageId[region]) {
                alerts.push(dsl.pass({message: "REGION: " + region + " - Instance ID " + instanceId + " is running Golden AMI " + imageId}));
            } else {
                alerts.push(dsl.fail({message: "REGION: " + region + " - Instance ID " + instanceId + " is NOT running Golden AMI " + goldenImageId[region] + " — Actual AMI => " + imageId}));
            }
        })
    });

    return alerts
  } catch (err) {
    return dsl.error({ error: err.message });
  }
}

