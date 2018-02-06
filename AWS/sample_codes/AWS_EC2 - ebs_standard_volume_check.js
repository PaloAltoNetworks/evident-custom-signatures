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

// Description: 
// (javascript) This signature checks each volume in a region and determines if the type of the volume is 'standard'
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
          resource_id: volume.volume_id,
          message: fail_message
        }));

      } else {

        var pass_message = 'volume with id ' + volume.volume_id
        pass_message += ' is of type ' + volume.volume_type;

        alerts.push(dsl.pass({
          resource_id: volume.volume_id,
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
