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

# Description:
# Check for EC2 Instance Profile against corporate standards
# John Martinez (john@evident.io)

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

