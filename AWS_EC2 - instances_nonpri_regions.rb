# Copyright (c) 2013, 2014, 2015, 2016, 2017. Evident.io (Evident). All Rights Reserved. 
# 
#   Evident.io shall retain all ownership of all right, title and interest in and to 
#   the Licensed Software, Documentation, Source Code, Object Code, and API's ("Deliverables"), 
#   including (a) all information and technology capable of general application to Evident.io's
#   customers; and (b) any works created by Evident.io prior to its commencement of any
#   Services for Customer.
# 
# Upon receipt of all fees, expenses and taxes due in respect of the relevant Services, 
#   Evident.io grants the Customer a perpetual, royalty-free, non-transferable, license to 
#   use, copy, configure and translate any Deliverable solely for internal business operations
#   of the Customer as they relate to the Evident.io platform and products, and always
#   subject to Evident.io's underlying intellectual property rights.
# 
# IN NO EVENT SHALL EVIDENT.IO BE LIABLE TO ANY PARTY FOR DIRECT, INDIRECT, SPECIAL, 
#   INCIDENTAL, OR CONSEQUENTIAL DAMAGES, INCLUDING LOST PROFITS, ARISING OUT OF 
#   THE USE OF THIS SOFTWARE AND ITS DOCUMENTATION, EVEN IF EVIDENT.IO HAS BEEN HAS BEEN
#   ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
# 
# EVIDENT.IO SPECIFICALLY DISCLAIMS ANY WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
#   THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE. 
#   THE SOFTWARE AND ACCOMPANYING DOCUMENTATION, IF ANY, PROVIDED HEREUNDER IS PROVIDED "AS IS". 
#   EVIDENT.IO HAS NO OBLIGATION TO PROVIDE MAINTENANCE, SUPPORT, UPDATES, ENHANCEMENTS,
#   OR MODIFICATIONS.
# 
# Description:
# Check to see if there are any instances running in a non-priority region (valid_regions).
#
# Default Conditions:
# - PASS: No instances were found in a running or stopped state in the region
# - FAIL: Instances were found in a running or stopped state in the region
#

configure do |c|
  c.valid_regions   = [:eu_west_1, :ap_northeast_1]
  c.deep_inspection = [:instance_id, :instance_state]
end

def perform(aws)
  region = aws.region
  resp   = aws.ec2.describe_instances(filters:[ {name: "instance-state-name", values: ["running", "stopped"] }]).reservations
  if resp.empty?
      pass(message: "No instances found in region, #{region}.")
  else
    resp.each do |resv|
      resv.instances.each do |inst|
        instance_id    = inst.instance_id
        instance_state = inst.state.name
        set_data(instance_id: instance_id, instance_state: instance_state)
        fail(message: "#{instance_id} is #{instance_state} in region, #{region}.", resource_id: instance_id)
      end
    end
  end
end
