//
// ec2_only_micro.js - @billautomata
// PROVIDED AS IS WITH NO WARRANTY OR GUARANTEES
//
//  This signature checks each instance in a region and determines if the
//  name of the instance_type contains the string 'micro'
//
//  If the instance is not micro it returns a failed alert, otherwise it passes.
//
//  You can change the type of instance in the string_to_check_for variable
//  to enforce your security policy.
//

dsl.configure(function(c) {
  c.valid_regions = ['us_east_1'];
  c.identifier = 'AWS:EC2-707';
  c.deep_inspection = ['instance_type','instance_id'];
  c.unique_identifier = [ 'instance_id' ];
});

function perform(aws) {
  try {

    var region = aws.region;
    var alerts = [];
    var reservations = aws.ec2.describe_instances().reservations;

    var string_to_check_for = 'micro'

    reservations.map(function(element) {
      element.instances.map(function(instance) {

        var report = {
          instance_type: instance.instance_type,
          instance_id: instance.instance_id
        };
        dsl.set_data(report);

        if (instance.instance_type.indexOf(string_to_check_for) === -1) {

          var fail_message = 'instance with id '
          fail_message += instance.instance_id
          fail_message += ' is not a micro instance. It is of the type : '
          fail_message += instance.instance_type

          alerts.push(dsl.fail({
            resource_id: instance.instance_id,
            message: fail_message
          }));

        } else {

          var pass_message = 'instance with id '
          pass_message += instance.instance_id + ' is a micro instance.'

          alerts.push(dsl.pass({
            resource_id: instance.instance_id,
            message: pass_message
          }));

        }

      })
    })

    return alerts;

  } catch (err) {
    return dsl.error({
      errors: err.message
    });
  }
}
