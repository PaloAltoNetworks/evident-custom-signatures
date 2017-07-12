# Copyright (c) 2017 Evident.io, Inc., All Rights Reserved
#
# Description:
# Ensure that ALB has access log enabled
#
# Default Condition:
# PASS: Access log is enabled on ALB
# FAIL: Access log is disabled on ALB
#
# Resolution/Remediation:
# - Go to EC2 console
# - Select "Load Balancers" from the left navigation menu
# - Select the ALB name
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
  # Case sensitivity when comparing the tag key & value
  case_insensitive: true,

  # When a resource fails the check, resources with matching tags will
  # generate WARN alert instead of FAIL
  # Example:
  # warn_only_on_tag: [
  #         {key: "environment", value: "stage"},
  #         {key: "environment", value: "dev*"}
  #]
  # For wildcard, use *  . If set value: "*", it will match everything inside of 'value'.
  # You can use it if you want to ensure that the tag exists (regardless what the value is)
  #
  # WARNING: Pulling tags requires an additional API call for each ALB. Therefore, tag information will be pulled only
  #          if you have one or more tags specified in 'warn_only_on_tag'
  warn_only_on_tag: []
}


#    ______   ____  ____   ________     ______   ___  ____     ______   
#  .' ___  | |_   ||   _| |_   __  |  .' ___  | |_  ||_  _|  .' ____ \  
# / .'   \_|   | |__| |     | |_ \_| / .'   \_|   | |_/ /    | (___ \_| 
# | |          |  __  |     |  _| _  | |          |  __'.     _.____`.  
# \ `.___.'\  _| |  | |_   _| |__/ | \ `.___.'\  _| |  \ \_  | \____) | 
#  `.____ .' |____||____| |________|  `.____ .' |____||____|  \______.' 
                                                                      
# deep inspection attribute will be included in each alert
configure do |c|
    c.deep_inspection   = [:load_balancer_arn, :load_balancer_name, :created_time, :load_balancer_attributes, :tags ]
end


def perform(aws)
  aws.elbv2.describe_load_balancers[:load_balancers].each do | lb |
    set_data(lb)

    lb_name = lb[:load_balancer_name]
    lb_arn = lb[:load_balancer_arn]

    lb_attributes = aws.elbv2.describe_load_balancer_attributes(load_balancer_arn: lb_arn)[:attributes]
    set_data(load_balancer_attributes: lb_attributes)


    # If ALB has access log enabled, send PASS alert and no need to grab the ALB tags
    access_log_enabled = false
    lb_attributes.each do | lb_attr |
      access_log_enabled = true if lb_attr[:key] == "access_logs.s3.enabled" and (lb_attr[:value] == "true" or lb_attr[:value] == true)
    end

    if access_log_enabled
      pass(message: "ALB #{lb_name} has access log enabled", resource_id: lb_name)
      next
    end

    # we need a separate call to get ALB tags.
    # So, tag is grabbed only if necessary
    if @options[:warn_only_on_tag].count > 0
      tags = []
      aws.elbv2.describe_tags(resource_arns: [lb_arn])[:tag_descriptions].each do | tag_descriptions |
        tags = tag_descriptions[:tags] if tag_descriptions[:resource_arn] == lb_arn
      end
      set_data(tags: tags)
    end

    if @options[:warn_only_on_tag].count > 0 and get_tag_matches(@options[:warn_only_on_tag], tags ).count > 0
      warn(message: "Access log is disabled on ALB #{lb_name}. Alert set to warn due to the tags", resource_id: lb_name, warn_only_on_tag: @options[:warn_only_on_tag])
    else
      fail(message: "Access log is disabled on ALB #{lb_name}.", resource_id: lb_name)
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