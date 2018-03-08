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
# Check EC2 instances for approved AMI
# 
# Default Conditions:
# - PASS: EC2 running approved AMI
# - FAIL: EC2 running non-approved AMI
#

#    ______     ___     ____  _____   ________   _____     ______   
#  .' ___  |  .'   `.  |_   \|_   _| |_   __  | |_   _|  .' ___  |  
# / .'   \_| /  .-.  \   |   \ | |     | |_ \_|   | |   / .'   \_|  
# | |        | |   | |   | |\ \| |     |  _|      | |   | |   ____  
# \ `.___.'\ \  `-'  /  _| |_\   |_   _| |_      _| |_  \ `.___]  | 
#  `.____ .'  `.___.'  |_____|\____| |_____|    |_____|  `._____.'  
# Configurable options                                                                  
@options = {
  # List of approved AMIs
  # Example:
  # approved_amis: [
  #   'ami-12345',
  #   'ami-23456'
  # ],
  #
  approved_amis: [
  ],

  # Use this option if you want to also whitelist image based on the image name's regex
  approved_image_with_regex: [
    /^amzn-ami-hvm-/i,
  ],

  # Use this option if you regularly publish new images
  # For example:
  # approved_image_with_tags: [
  #   {key: "approved", value: "yes"},
  #   {key: "generator", value: "jen*"}
  #  ],
  approved_image_with_tags: [

  ],

  # instance status to be included
  # Valid values: 
  # (pending | running | shutting-down | terminated | stopping | stopped).
  instance_status: [
    "pending",
    "running",
    "shutting-down",
    "stopping",
    "stopped"
  ],

  # When a resource has one or more matching tags, the resource will be excluded from the checks
  # and a PASS alert is generated
  # Example:
  # exclude_on_tag: [
  #     {key: "environment", value: "demo"},
  #     {key: "environment", value: "dev*"}
  # ]
  # For wildcard, use *  . If set value: "*", it will match any value inside of the tag
  #
  # WARNING: For some AWS Services, pulling tags may require additional API call. 
  #          Therefore, tag information will be pulled
  #          if there is one or more tags specified in 'exclude_on_tag'
  exclude_on_tag: [],

  # Case sensitivity when comparing the tag key & value
  case_insensitive: true,

}

#    ______   ____  ____   ________     ______   ___  ____     ______   
#  .' ___  | |_   ||   _| |_   __  |  .' ___  | |_  ||_  _|  .' ____ \  
# / .'   \_|   | |__| |     | |_ \_| / .'   \_|   | |_/ /    | (___ \_| 
# | |          |  __  |     |  _| _  | |          |  __'.     _.____`.  
# \ `.___.'\  _| |  | |_   _| |__/ | \ `.___.'\  _| |  \ \_  | \____) | 
#  `.____ .' |____||____| |________|  `.____ .' |____||____|  \______.' 
                                                                      
# deep inspection attribute will be included in each alert
configure do |c|
    c.deep_inspection   = [:instance_id, :image_id, :launch_time, :platform, :state, :vpc_id, :subnet_id, :tags, :options]
end

def perform(aws)
  @cached_images = {}

  next_token = nil
  while next_token!= "end"
    resp = aws.ec2.describe_instances({
      filters: [{name: "instance-state-name", values: @options[:instance_status]}],
      next_token: next_token,
      max_results: 5
      })

    if resp.key?("next_token") and resp[:next_token] != ""
      next_token = resp[:next_token]
    else
      next_token = "end"
    end

    resp[:reservations].each do | reservation |
      reservation[:instances].each do | instance |
        tags = instance[:tags]
        instance_id = instance[:instance_id]

        set_data(
          instance_id: instance_id,
          image_id: instance[:image_id],
          launch_time: instance[:launch_time],
          platform: instance[:platform],
          state: instance[:state],
          vpc_id: instance[:vpc_id],
          subnet_id: instance[:subnet_id],
          tags: instance[:tags],
          options: @options
          )

        # See if the instance should be skipped based on its tags
        if @options[:exclude_on_tag].count > 0 and get_tag_matches(@options[:exclude_on_tag], tags).count > 0
          pass(message: "Instance #{instance_id} is skipped due to the tags", exclude_on_tag: @options[:exclude_on_tag], resource_id: instance_id)
          next
        end

        if @options[:approved_amis].include?(instance[:image_id])
          pass(message: "Instance #{instance_id} uses approved AMI", resource_id: instance_id)
          next
        end

        # Check if image is whitelisted based on the image's tags
        image_details = get_image_details(aws, instance[:image_id])
        if @options[:approved_image_with_tags].count > 0 and  get_tag_matches(@options[:approved_image_with_tags], image_details[:tags]).count > 0
          pass(message: "Instance #{instance_id} uses approved AMI (whitelisted through image tags). ", resource_id: instance_id, image_details: image_details)
          next
        end

        # Check if image is whitelisted based on the image name
        whitelist_based_on_image_name = false
        @options[:approved_image_with_regex].each do | regex |
          whitelist_based_on_image_name = true if image_details[:name].match(regex)
        end
        
        if whitelist_based_on_image_name
          pass(message: "Instance #{instance_id} uses approved AMI (whitelisted throuhg image name)", resource_id: instance_id, image_details: image_details)
        else
          fail(message: "Instance #{instance_id} does not use approved AMI", resource_id: instance_id)
        end

      end
    end
  end
  
end


def get_image_details(aws,image_id)
  return @cached_images[image_id] if @cached_images.include?(image_id)

  image_details = aws.ec2.describe_images(image_ids: [image_id])[:images][0]
  if image_details.key?("tags")
    tags = image_details[:tags]
  else
    tags = []
  end

  @cached_images[image_id] = {
    name: image_details[:name],
    tags: tags
  }

  return @cached_images[image_id]
end

# Return the number of matching tags if one of the tag key-value pair matches
def get_tag_matches(option_tags, aws_tags)
  matches = []

  option_tags.each do | option_tag |
    # If tag value is a string, do string comparison (with wildcard support)
    if option_tag[:value].is_a? String
      option_value = option_tag[:value].sub('*','.*')

      aws_tags.each do | aws_tag | 
        if @options[:case_insensitive]
          value_pattern = /^#{option_value}$/i
          matches.push(aws_tag) if option_tag[:key].downcase == aws_tag[:key].downcase and aws_tag[:value].match(value_pattern)
        else
          value_pattern = /^#{option_value}$/
          matches.push(aws_tag) if option_tag[:key] == aws_tag[:key] and aws_tag[:value].match(value_pattern)
        end          
      end

    # if tag value is an array, check if value is in the array
    else
      if @options[:case_insensitive]
        option_values = option_tag[:value].map(&:downcase)
      else
        option_values = option_tag[:value]
      end

      aws_tags.each do | aws_tag |
        if @options[:case_insensitive]
          matches.push(aws_tag) if (option_tag[:key].downcase == aws_tag[:key].downcase && (option_values.include?(aws_tag[:value].downcase)))
        else
          matches.push(aws_tag) if (option_tag[:key] == aws_tag[:key] && (option_values.include?(aws_tag[:value])))
        end
      end
    end
  end

  return matches
end