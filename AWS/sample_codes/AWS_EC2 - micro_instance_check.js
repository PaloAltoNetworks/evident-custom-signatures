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
// (javascript) Check if EC2 instance type contains the string 'micro'
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
