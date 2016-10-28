##
## ec2_instance_maintenance_event_check.rb - John Martinez (john@evident.io)
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
    c.deep_inspection   = [:instance_state, :events, :tags]
    c.unique_identifier = [:instance_id]
end

def perform(aws)
    
    aws.ec2.describe_instances.reservations.map(&:instances).flatten.each do |instance|
        
        instance_id  = instance[:instance_id]
        tags = instance[:tags]
        status = nil

        instance_statuses = aws.ec2.describe_instance_status({ instance_ids: [ instance_id ] }).instance_statuses
        
        instance_statuses.each do |status|

            instance_state = status.instance_state[:name]
            events = status.events
            
            set_data(instance_state: instance_state, events: events, tags: tags)
            
            if instance_state == "running"
                if events.count > 0
                    warn(message: "Instance #{instance_id} has upcoming maintenance events", resource_id: instance_id)
                else
                    pass(message: "Instance #{instance_id} has no upcoming maintenance events", resource_id: instance_id)
                end
            end
            
        end    
    
    end

end
