//
// ec2_instance_age.js - John Martinez (john@evident.io)
// PROVIDED AS IS WITH NO WARRANTY OR GUARANTEES
//
dsl.configure(function(c){
  c.deep_inspection   = ['instance_id', 'launch_time', 'time_now'];
});

function perform(aws) {
  try {
    var alerts  = [];
    var reservations = aws.ec2.describe_instances().reservations;
    var region = aws.region;

    reservations.map(function(reservation) {
        var reservationId = reservation.reservation_id;
        var instances = reservation.instances;
        var now = new Date();
        var timeNow = now.getTime();

        instances.map(function(instance) {
            var instanceId = instance.instance_id;
            var imageId = instance.image_id;
            var launchTime = instance.launch_time;
            var ld = new Date(launchTime);
            var lt = ld.getTime();

            var timeDiff = timeNow - launchTime;

            var report = { instance_id: instanceId, launch_time: launchTime };
            dsl.set_data(report);

            if (timeDiff < 43200000) {
                alerts.push(dsl.pass({resource_id: instanceId, message: "Instance " + instanceId + " is newer than 12 hours"}));
            } else if (timeDiff >= 43200000 && timeDiff < 86400000 ) {
                alerts.push(dsl.warn({resource_id: instanceId, message: "Instance " + instanceId + " is older than 12 hours"}));
            } else if (timeDiff >= 86400000) {
                alerts.push(dsl.fail({resource_id: instanceId, message: "Instance " + instanceId + " is older than 24 hours"}));
            }
        })
    });

    return alerts
  } catch (err) {
    return dsl.error({ errors: err.message });
  }
}

