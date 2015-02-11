//
// ec2_only_micro.js - @billautomata
// PROVIDED AS IS WITH NO WARRANTY OR GUARANTEES
//
//  This signature checks each volume in a region and determines if the
//  type of the volume is 'standard'
//
//  If the volume is not of the type 'standard' it fails the alert
//
//  You can change the type of volume in the type_to_check_for variable
//  to enforce your security policy.
//

dsl.configure(function(c) {
  c.valid_regions     = ['us_east_1'];                  // Only run in us_east_1
  c.display_as        = 'global';                       // Display as region global instead of region us_east_1
  c.deep_inspection   = ['users'];                      // Required
  c.unique_identifier = [{'user_name': 'user_id'}];     // Required
});

function perform(aws) {
  try {

    var region = aws.region;
    var alerts  = [];
    var reservations = aws.ec2.describe_instances().reservations;
    var volumes = aws.ec2.describe_volumes().volumes;

    var type_to_check_for = 'standard'

    volumes.map(function(volume){


        if(volume.volume_type !== type_to_check_for){
            var fail_message = 'volume with id ' + volume.volume_id + ' is of type ' + volume.volume_type + ' and not of type ' + type_to_check_for;
            alerts.push(dsl.fail({message:fail_message}));
        } else {
            var pass_message = 'volume with id ' + volume.volume_id + ' is of type ' + volume.volume_type;
            alerts.push(dsl.pass({message:pass_message}));
        }

    })

    return alerts;

  } catch (err) {
    return dsl.error({ errors: err.message });
  }
}
