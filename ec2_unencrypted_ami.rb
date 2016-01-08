## 
## ec2_encrypted_ami.rb: Check for Unencrypted AMI
##
## PROVIDED AS IS WITH NO WARRANTY OR GUARANTEES
## Copyright (c) 2015 Evident.io, Inc., All Rights Reserved
##
## Description:
## Instances not based on encrypted EBS root volumes poses a threat of data snooping.
## This signatures checks for AMIs that are based on unencrypted root volume snapshots.
## 
## Resolution:
## Encrypt all AMIs by following these stepts: (TBD)
##
configure do |c|
    c.deep_inspection = [:image_id, :name, :description, :root_device_name, :tags, :block_device_mappings]
    c.unique_identifier  = [:image_id]
end

# Required perform method
def perform(aws)
    @images = aws.ec2.describe_images({owners: ["self"]}).images
    alert_images()
end

def alert_images()
    @images.each do |image|
        image_id = image[:image_id]
        root_device_name = image[:root_device_name]
        root_device_type = image[:root_device_type]
        is_encrypted = nil
        set_data(image)
        image.block_device_mappings.each do |block_device|
            device_name = block_device[:device_name]
            if root_device_type == "ebs" && device_name == root_device_name
                is_encrypted = block_device.ebs[:encrypted]
                if is_encrypted == true
                    pass(message: "AMI #{image_id} is based on an encrypted root snapshot", resource_id: image_id, is_encrypted: is_encrypted)
                else
                    fail(message: "AMI #{image_id} is based on an unencrypted root snapshot", resource_id: image_id, is_encrypted: is_encrypted)
                end
            end
        end
    end
end
