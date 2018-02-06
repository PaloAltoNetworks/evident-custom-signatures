//
// Copyright (c) 2013, 2014, 2015, 2016, 2017, 2018. Evident.io (Evident). All Rights Reserved. 
//   Evident.io shall retain all ownership of all right, title and interest in and to 
//   the Licensed Software, Documentation, Source Code, Object Code, and API's ("Deliverables"), 
//   including (a) all information and technology capable of general application to Evident.io's customers; 
//   and (b) any works created by Evident.io prior to its commencement of any Services for Customer. 
//
// Upon receipt of all fees, expenses and taxes due in respect of the relevant Services, 
//   Evident.io grants the Customer a perpetual, royalty-free, non-transferable, license to 
//   use, copy, configure and translate any Deliverable solely for internal business operations of the Customer 
//   as they relate to the Evident.io platform and products, 
//   and always subject to Evident.io's underlying intellectual property rights.
//
// IN NO EVENT SHALL EVIDENT.IO BE LIABLE TO ANY PARTY FOR DIRECT, INDIRECT, SPECIAL, 
//   INCIDENTAL, OR CONSEQUENTIAL DAMAGES, INCLUDING LOST PROFITS, ARISING OUT OF 
//   THE USE OF THIS SOFTWARE AND ITS DOCUMENTATION, 
//   EVEN IF EVIDENT.IO HAS BEEN ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//
// EVIDENT.IO SPECIFICALLY DISCLAIMS ANY WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
//  THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE. 
//  THE SOFTWARE AND ACCOMPANYING DOCUMENTATION, IF ANY, PROVIDED HEREUNDER IS PROVIDED "AS IS". 
//  EVIDENT.IO HAS NO OBLIGATION TO PROVIDE MAINTENANCE, SUPPORT, UPDATES, ENHANCEMENTS, OR MODIFICATIONS.
//

//
// Description:
// (javascript) This signature checks each instance in a region and determines if there are tags set.
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
            resource_id: instance.instance_id,
            message: fail_message
          }));

        } else {

          var pass_message = 'instance with id '
          pass_message += instance.instance_id
          pass_message += ' has tags set. It has ' + tags_length + ' tag(s).'

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
