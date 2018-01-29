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
// (javascript) Check for EC2 instance age
// John Martinez (john@evident.io)
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

