//
// ec2_enforce_volume_type.js - @billautomata
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
  c.valid_regions = ['us_east_1'];
  c.identifier = 'AWS:EC2-909'
  c.deep_inspection = ['volume_type', 'volume_id'];
  c.unique_identifier = ['volume_id'];
});

function perform(aws) {
  try {

    var region = aws.region;
    var alerts = [];
    var volumes = aws.ec2.describe_volumes().volumes;

    var type_to_check_for = 'standard'

    volumes.map(function(volume) {

      var report = {
        volume_type: volume.volume_type,
        volume_id: volume.volume_id
      };
      dsl.set_data(report);

      if (volume.volume_type !== type_to_check_for) {

        var fail_message = 'volume with id '
        fail_message += volume.volume_id + ' is of type '
        fail_message += volume.volume_type + ' and not of type '
        fail_message += type_to_check_for;

        alerts.push(dsl.fail({
          resource_id: volume_id,
          message: fail_message
        }));

      } else {

        var pass_message = 'volume with id ' + volume.volume_id
        pass_message += ' is of type ' + volume.volume_type;

        alerts.push(dsl.pass({
          resource_id: volume_id,
          message: pass_message
        }));

      }

    })

    return alerts;

  } catch (err) {
    return dsl.error({
      errors: err.message
    });
  }
}
