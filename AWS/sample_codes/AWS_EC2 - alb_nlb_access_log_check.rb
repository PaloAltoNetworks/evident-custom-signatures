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
# Ensure that ALB/NLB has access log enabled
#
# Default Condition:
# PASS: Access log is enabled 
# FAIL: Access log is not enabled
#
# Resolution/Remediation:
# - Go to EC2 console
# - Select "Load Balancers" from the left navigation menu
# - Select the load balancer name
# - Under the Attributes section on the lower panel, select "Edit Attributes"
# - Check the "Enable Access Log"
# - Specify the target S3 bucket
# - Hit "Save"
#

#    ______     ___     ____  _____   ________   _____     ______   
#  .' ___  |  .'   `.  |_   \|_   _| |_   __  | |_   _|  .' ___  |  
# / .'   \_| /  .-.  \   |   \ | |     | |_ \_|   | |   / .'   \_|  
# | |        | |   | |   | |\ \| |     |  _|      | |   | |   ____  
# \ `.___.'\ \  `-'  /  _| |_\   |_   _| |_      _| |_  \ `.___]  | 
#  `.____ .'  `.___.'  |_____|\____| |_____|    |_____|  `._____.'  
# Configurable options                                                                  
@options = {  
  # List of approved target S3 bucket
  # Case sensitive
  #
  # If approved_target_bucket is left empty, PASS alert is generated 
  #   as long as logging to S3 bucket is enabled.
  # If not empty, the target bucket needs to match one of the bucket 
  #   specified in the approved_target_bucket list
  #
  # Example:
  # approved_target_bucket: ["my_lb_logs", "central_lb_logs"],
  approved_target_bucket: [],

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
    c.deep_inspection   = [:load_balancer_arn, :load_balancer_name, :created_time, :load_balancer_attributes, :type, :tags, :options]
end


def perform(aws)
  aws.elbv2.describe_load_balancers[:load_balancers].each do | lb |
    set_data(lb)
    set_data(options: @options)

    lb_name = lb[:load_balancer_name]
    lb_arn = lb[:load_balancer_arn]

    lb_attributes = aws.elbv2.describe_load_balancer_attributes(load_balancer_arn: lb_arn)[:attributes]
    set_data(load_balancer_attributes: lb_attributes)


    # We need a separate call to get ELBv2 tags. So, tag is grabbed only if necessary
    if @options[:exclude_on_tag].count > 0
      tags = []
      aws.elbv2.describe_tags(resource_arns: [lb_arn])[:tag_descriptions].each do | tag_descriptions |
        tags = tag_descriptions[:tags] if tag_descriptions[:resource_arn] == lb_arn
      end
      set_data(tags: tags)

      if get_tag_matches(@options[:exclude_on_tag], tags ).count > 0
        pass(message: "Load balancer #{lb_name} is excluded from the check due to the tags.", resource_id: lb_name)
        next
      end
    end

    access_log_enabled = false
    matching_target_bucket = false
    lb_attributes.each do | lb_attr |
      access_log_enabled = true if lb_attr[:key] == "access_logs.s3.enabled" and (lb_attr[:value] == "true" or lb_attr[:value] == true)
      matching_target_bucket = true if lb_attr[:key] == "access_logs.s3.bucket" and @options[:approved_target_bucket].include?(lb_attr[:value])
    end

    if access_log_enabled
      # access log is enabled. check the target bucket requirement
      if @options[:approved_target_bucket].count > 0 
        if matching_target_bucket
          pass(message: "Load Balancer #{lb_name} has access log enabled to the approved S3 bucket", resource_id: lb_name)
        else
          fail(message: "Load Balancer #{lb_name} has access log enabed to unapproved S3 bucket", resource_id: lb_name)
        end
      else
        pass(message: "Load Balancer #{lb_name} has access log enabled", resource_id: lb_name)
      end
    
    else
      fail(message: "Load Balancer #{lb_name} does not have access log enabled.", resource_id: lb_name)
    end

  end
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