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
// Check for S3 logging, similar to standard signature AWS:SSS-009

dsl.configure(function(c){
    c.deep_inspection   = ['bucket', 'bucketName', 'logging'];
});

function perform(aws) {
    try {
        var buckets = aws.s3.list_buckets().buckets;
        var alerts  = [];

        buckets.map(function(bucket) {
            var bucketName = bucket.name;
            var bucket_log = aws.s3.get_bucket_logging({ bucket: bucketName });
            var report = { bucket: bucket, bucketName: bucketName, logging: bucket_log };
            dsl.set_data(report);

            if (bucket_log.logging_enabled) {
                alerts.push(dsl.pass({resource_id: bucketName, message: "Bucket " + bucketName + " has logging enabled"}))
            } else {
                alerts.push(dsl.fail({resource_id: bucketName, message: "Bucket " + bucketName + " does not have logging enabled"}))
            }
        });

        return alerts
    } catch (err) {
        return dsl.error({ errors: err.message });
    }
}
