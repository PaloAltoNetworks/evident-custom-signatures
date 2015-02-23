//
// ec2_no_tags.js - @billautomata
// PROVIDED AS IS WITH NO WARRANTY OR GUARANTEES
//
//  This signature checks each instance in a region and determines if there
//  are tags set.
//
//  If the instance has no tags it returns a failure.  Otherwise it returns a
//  pass with an indication of how many tags there are.
//
//  You can change the number of tags to suit your security policy.
//

dsl.configure(function(c) {
  c.valid_regions = ['us_east_1'];
  c.identifier = 'AWS:EC2-303';
  c.deep_inspection = ['tags','instance_id','tags_length'];
  c.unique_identifier = [ 'instance_id' ];
});

function perform(aws) {
  try {

    var region = aws.region;
    var alerts = [];
    var reservations = aws.ec2.describe_instances().reservations;

    reservations.map(function(element) {
      element.instances.map(function(instance) {

        var report = {
          tags: instance.tags,
          instance_id: instance.instance_id,
          tags_length: instance.tags.length
        };

        dsl.set_data(report);

        var tags_length = instance.tags.length

        if (tags_length === 0) {

          var fail_message = 'instance with id '
          fail_message += instance.instance_id
          fail_message += ' has no tags set.'

          alerts.push(dsl.fail({
            message: fail_message
          }));

        } else {

          var pass_message = 'instance with id '
          pass_message += instance.instance_id
          pass_message += ' has tags set. It has ' + tags_length + ' tag(s).'

          alerts.push(dsl.pass({
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
