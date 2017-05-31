## 
## ec2_public_ami.rb: Check for Public AMI
##
## PROVIDED AS IS WITH NO WARRANTY OR GUARANTEES
## Copyright (c) 2015 Evident.io, Inc., All Rights Reserved
##
## Description:
## AMIs can be shared publicly, but in almost all cases should not due to risk
## in exposing sensitive data.
## 
## Resolution:
## In the AWS Console:
## * Open the Amazon EC2 console at https://console.aws.amazon.com/ec2/.
## * In the navigation pane, choose AMIs.
## * Select your AMI in the list, and then choose Modify Image Permissions from the Actions list.
## * Choose Private and choose Save.
##
## Note:
## Similar to standard signature AWS:EC2-036
##
## In the aws-cli:
## * aws ec2 modify-image-attribute --image-id ami-XXXXXXXX --launch-permission "{\"Remove\":[{\"Group\":\"all\"}]}"


##
configure do |c|
    c.deep_inspection = [:image_id, :name, :description, :public, :tags]
end

# Required perform method
def perform(aws)
    @images = aws.ec2.describe_images({owners: ["self"]}).images
    alert_images()
end

def alert_images()
    @images.each do |image|
        image_id = image[:image_id]
        is_public = image[:public]
        set_data(image)
        
        if is_public == true
            fail(message: "AMI #{image_id} is shared publicly", resource_id: image_id)
        else
            pass(message: "AMI #{image_id} is private", resource_id: image_id)
        end
        
        
    end
end
