#
# Copyright (c) 2013, 2014, 2015, 2016, 2017, 2018. Evident.io (Evident). All Rights Reserved. 
#   Evident.io shall retain all ownership of all right, title and interest in and to 
#   the Licensed Software, Documentation, Source Code, Object Code, and API's ("Deliverables"), 
#   including (a) all information and technology capable of general application to Evident.io's customers; 
#   and (b) any works created by Evident.io prior to its commencement of any Services for Customer. 
#
# Upon receipt of all fees, expenses and taxes due in respect of the relevant Services, 
#   Evident.io grants the Customer a perpetual, royalty-free, non-transferable, license to 
#   use, copy, configure and translate any Deliverable solely for internal business operations of the Customer 
#   as they relate to the Evident.io platform and products, 
#   and always subject to Evident.io's underlying intellectual property rights.
#
# IN NO EVENT SHALL EVIDENT.IO BE LIABLE TO ANY PARTY FOR DIRECT, INDIRECT, SPECIAL, 
#   INCIDENTAL, OR CONSEQUENTIAL DAMAGES, INCLUDING LOST PROFITS, ARISING OUT OF 
#   THE USE OF THIS SOFTWARE AND ITS DOCUMENTATION, 
#   EVEN IF EVIDENT.IO HAS BEEN ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
# EVIDENT.IO SPECIFICALLY DISCLAIMS ANY WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
#  THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE. 
#  THE SOFTWARE AND ACCOMPANYING DOCUMENTATION, IF ANY, PROVIDED HEREUNDER IS PROVIDED "AS IS". 
#  EVIDENT.IO HAS NO OBLIGATION TO PROVIDE MAINTENANCE, SUPPORT, UPDATES, ENHANCEMENTS, OR MODIFICATIONS.
#

#
# Description:
# Check for upcoming instance maintenance event
# 
# Default Conditions:
# - PASS: Instance has no upcoming maintenance event
# - WARN: Instance has upcoming maintenance event 
# - FAIL: Instance has upcoming maintenance event in less than 7 days
#
# Resolution/remediation:
# No action needed if the affected instance is in an Auto Scaling group that will accommodate for the 
# instance going offline or being terminated. Otherwise, take corrective action to replace the instance 
# with another one (stop and restart)
#

configure do |c|
    c.deep_inspection   = [:days_left, :instance_state, :events, :tags]
    c.unique_identifier = [:instance_id]
end

def perform(aws)
    
    now = Time.now

    aws.ec2.describe_instances.reservations.map(&:instances).flatten.each do |instance|
        
        instance_id  = instance[:instance_id]
        tags = instance[:tags]
        status = nil

        instance_statuses = aws.ec2.describe_instance_status({ instance_ids: [ instance_id ] }).instance_statuses
        
        instance_statuses.each do |status|

            instance_state = status.instance_state[:name]
            events = status.events
            not_before = nil
            
            events.each do |event|
                not_before = event[:not_before].to_datetime
            end
            
            delta = not_before.to_i - now.to_i
            days_left = delta / 86400

            if instance_state == "running"
                if events.count > 0
                    set_data(days_left: days_left, instance_state: instance_state, events: events, tags: tags)

                    if days_left < 7
                        fail(message: "Instance #{instance_id} has maintenance events in less than 7 days", resource_id: instance_id)
                    else
                        warn(message: "Instance #{instance_id} has upcoming maintenance events", resource_id: instance_id)
                    end
                else
                    days_left = nil
                    set_data(days_left: days_left, instance_state: instance_state, events: events, tags: tags)
                    pass(message: "Instance #{instance_id} has no upcoming maintenance events", resource_id: instance_id)
                end
            end
            
        end    
    
    end

end
