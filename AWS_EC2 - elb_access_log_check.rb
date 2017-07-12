# Copyright (c) 2017 Evident.io, Inc., All Rights Reserved
#
# Description:
# Ensure that ELB has access log enabled
#
# Default Condition:
# PASS: Access log is enabled on ELB
# FAIL: Access log is disabled on ELB
#
# Resolution/Remediation:
# - Go to EC2 console
# - Select "Load Balancers" from the left navigation menu
# - Select the ELB name
# - Under the Attributes section on the lower panel, select "Configure Access Log"
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
  # WARNING: Pulling tags requires an additional API call for each ELB. Therefore, tag information will be pulled only
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
  aws.elb.describe_load_balancers[:load_balancer_descriptions].each do | elb |
    set_data(elb)

    elb_name = elb[:load_balancer_name]
    elb_attr = aws.elb.describe_load_balancer_attributes(load_balancer_name: elb_name)[:load_balancer_attributes]
    set_data(load_balancer_attributes: elb_attr)


    # If ELB has access log enabled, send PASS alert and no need to grab the ELB tags
    if elb_attr[:access_log][:enabled]
      pass(message: "ELB #{elb_name} has access log enabled", access_log: elb_attr[:access_log], resource_id: elb_name)
      next
    end

    # we need a separate call to get ELB tags.
    # So, tag is grabbed only if necessary
    if @options[:warn_only_on_tag].count > 0
      tags = []
      aws.elb.describe_tags(load_balancer_names: [elb_name])[:tag_descriptions].each do | tag_descriptions |
        tags = tag_descriptions[:tags] if tag_descriptions[:load_balancer_name] == elb_name
      end
      set_data(tags: tags)
    end

    if @options[:warn_only_on_tag].count > 0 and get_tag_matches(@options[:warn_only_on_tag], tags ).count > 0
      warn(message: "Access log is disabled on ELB #{elb_name}. Alert set to warn due to the tags", resource_id: elb_name, warn_only_on_tag: @options[:warn_only_on_tag])
    else
      fail(message: "Access log is disabled on ELB #{elb_name}.", resource_id: elb_name)
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