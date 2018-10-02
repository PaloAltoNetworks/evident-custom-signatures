# Copyright (c) 2013, 2014, 2015, 2016, 2017, 2018. Evident.io (Evident). All Rights Reserved. 
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
#
# Ensure that your Amazon Machine Images (AMIs) are encrypted to fulfill compliance
# requirements for data-at-rest encryption.
# 
# Instances not based on encrypted EBS root volumes poses a threat of data snooping.
# This signatures checks for AMIs that are based on unencrypted root volume snapshots.
# 
# Default Conditions:
#
# - PASS: AMI is based on an encrypted root snapshot
# - FAIL: AMI is based on an unencrypted root snapshot
#
# Remediation:
#
# https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/AMIEncryption.html
#

#    ______   ____  ____   ________     ______   ___  ____     ______   
#  .' ___  | |_   ||   _| |_   __  |  .' ___  | |_  ||_  _|  .' ____ \  
# / .'   \_|   | |__| |     | |_ \_| / .'   \_|   | |_/ /    | (___ \_| 
# | |          |  __  |     |  _| _  | |          |  __'.     _.____`.  
# \ `.___.'\  _| |  | |_   _| |__/ | \ `.___.'\  _| |  \ \_  | \____) | 
#  `.____ .' |____||____| |________|  `.____ .' |____||____|  \______.' 
#

configure do |c|
  c.deep_inspection = [:image_id, :block_device_mappings, :region]
end

def perform(aws)

  images = aws.ec2.describe_images({ owners: ["self"] })[:images]
  region = aws.region

  images.each do | image |
    image_id         = image[:image_id]
    root_device_name = image[:root_device_name]
    root_device_type = image[:root_device_type]

    image.block_device_mappings.each do | block_device |
      next unless root_device_type == "ebs" && block_device[:device_name] == root_device_name
      
      is_encrypted = block_device[:ebs].encrypted
      set_data(image_id: image_id, block_device_mappings: block_device, region: region)

      if is_encrypted == true
        pass(message: "AMI #{image_id} is based on an encrypted root snapshot.", resource_id: image_id)
      else
        fail(message: "AMI #{image_id} is based on an unencrypted root snapshot.", resource_id: image_id)
      end
    end
  end
end
