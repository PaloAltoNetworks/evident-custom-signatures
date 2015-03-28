//
// ec2_cis_ami_microsoft_windows_2012_r2.js - Justin Lundy (jbl@evident.io)
// PROVIDED AS IS WITH NO WARRANTY OR GUARANTEES
//
// Checks us-east-1 and us-west-1 for EC2 Instances Running CIS Hardened
// Microsoft Windows Server 2012 R2 AMIs
// http://benchmarks.cisecurity.org/downloads/show-single/index.cfm?file=windows2012R2.110

dsl.configure(function(c){
  c.deep_inspection   = ['instance_id', 'actual_ami', 'cis_ami'];
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
            var cisImageId = { 
                "us_east_1": "ami-7bc3e04b",
                "us_west_2": "ami-7bc3e04b"
            };

            var report = { instance_id: instanceId, actual_ami: imageId, cis_ami: cisImageId};
            dsl.set_data(report);
            
            if (imageId == cisImageId[region]) {
                alerts.push(dsl.pass({resource_id: instanceId, message: "REGION: " + region + " - Instance ID " + instanceId + " is running the hardened CIS AMI " + imageId}));
            } else {
                alerts.push(dsl.fail({resource_id: instanceId, message: "REGION: " + region + " - Instance ID " + instanceId + " is NOT running the hardened CIS AMI " + cisImageId[region] + " — Actual AMI => " + imageId}));
            }
        })
    });

    return alerts
  } catch (err) {
    return dsl.error({ errors: err.message });
  }
}
