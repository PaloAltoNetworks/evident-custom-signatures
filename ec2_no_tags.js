//
// ec2_only_micro.js - @billautomata
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

    var string_to_check_for = 'micro'

    reservations.map(function(element){
        element.instances.map(function(instance){

          var tags_length = instance.tags.length

            if(tags_length === 0){
                var fail_message = 'instance with id ' + instance.instance_id + ' has no tags set.'
                alerts.push(dsl.fail({message: fail_message}));
            } else {
                var pass_message = 'instance with id ' + instance.instance_id +' has tags set. It has ' + tags_length + ' tag(s).'
                alerts.push(dsl.pass({message: pass_message}));
            }

        })
    })
    return alerts;

  } catch (err) {
    return dsl.error({ errors: err.message });
  }
}
