//
// ec2_instance_name_tag_check.js - John Martinez (john@evident.io)
// PROVIDED AS IS WITH NO WARRANTY OR GUARANTEES
//
dsl.configure(function(c){
  c.deep_inspection   = ['instance_id', 'tag_key', 'tag_value'];
});

function perform(aws) {
  try {
    var alerts  = [];
    var reservations = aws.ec2.describe_instances().reservations;

    reservations.map(function(reservation) {
        var reservationId = reservation.reservation_id;
        var instances = reservation.instances;

        instances.map(function(instance) {
            var instanceId = instance.instance_id;
            var tags = instance.tags;
            
            if (tags.length > 0) {
            
                tags.map(function(tag) {
                    var tagKey = tag.key;
                    var tagValue = tag.value;
                    var instanceTag = { 
                        "Name": "Demo123",
                        "Department": "Eng"
                    };

                    var report = { instance_id: instanceId, tag_key: tagKey, tag_value: tagValue };
                    dsl.set_data(report);
            
                    if (tagKey == "Name" && tagValue == instanceTag[tagKey]) {
                        alerts.push(dsl.pass({resource_id: instanceId, message: "Instance ID " + instanceId + " matches the correct Name tag " + instanceTag[tagKey]}));
                    } else if (tagKey == "Name" && tagValue != instanceTag[tagKey]) {
                        alerts.push(dsl.fail({resource_id: instanceId, message: "Instance ID " + instanceId + " does not match the correct Name tag " + instanceTag[tagKey]}));
                    }
                });
                
            } else {
                alerts.push(dsl.warn({resource_id: instanceId, message: "Instance ID " + instanceId + " does not have any tags associated with it"}))
            }
            
        });
        
    });

    return alerts
  } catch (err) {
    return dsl.error({ errors: err.message });
  }
}

