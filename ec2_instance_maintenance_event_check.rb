##
## ec2_instance_maintenance_event_check.rb - John Martinez (john@evident.io)
##
## Name: Instance Maintenance Event Check
##
## Severity Level: Medium
##
## Description
## Will report a warning if a running instance has scheduled maintenance events.
## 
## Resolution
## No action needed if the affected instance is in an Auto Scaling group that will accommodate for the 
## instance going offline or being terminated. Otherwise, take corrective action to replace the instance 
## with another one.
## 

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
