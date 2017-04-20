##
## ec2_instance_profile_name_check.rb - John Martinez (john@evident.io)
## PROVIDED AS IS WITH NO WARRANTY OR GUARANTEES
##
## Description:
## Instance Profile names should adhere to corporate standards
##

configure do |c|
  c.deep_inspection   = [:instance_id, :profile_arn, :tags]
end

def perform(aws)
    
    aws.ec2.describe_instances.reservations.map(&:instances).flatten.each do |instance|
        
        instance_id  = instance[:instance_id]
        tags = instance[:tags]
        
        if instance[:iam_instance_profile]
            
            profile_arn = instance[:iam_instance_profile].arn
            set_data(instance_id: instance_id, profile_arn: profile_arn, tags: tags)
            
            if (profile_arn =~ /arn:aws:iam::\d{12}:instance-profile\/Standard-Role/)
                pass(message: "The correct instance profile is assigned to instance #{instance_id}", resource_id: instance_id)
            else
                fail(message: "The instance profile assigned to instance #{instance_id} does not conform to instance role standards", resource_id: instance_id)
            end
            
        else
            
            set_data(instance_id: instance_id, profile_arn: profile_arn, tags: tags)
            warn(message: "No instance profile assigned to instance #{instance_id}", resource_id: instance_id)
            
        end
        
    end

end

