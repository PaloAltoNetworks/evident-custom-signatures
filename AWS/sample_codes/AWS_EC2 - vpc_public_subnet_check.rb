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
# Public Subnet (Internet Gateway) Check
# 
# Default Conditions:
# - PASS: Subnet's default route is not IGW
# - PASS: Subnet's default route is IGW, but the subnet is whitelisted.
# - FAIL: Subnet's default route is IGW
#

#    ______     ___     ____  _____   ________   _____     ______   
#  .' ___  |  .'   `.  |_   \|_   _| |_   __  | |_   _|  .' ___  |  
# / .'   \_| /  .-.  \   |   \ | |     | |_ \_|   | |   / .'   \_|  
# | |        | |   | |   | |\ \| |     |  _|      | |   | |   ____  
# \ `.___.'\ \  `-'  /  _| |_\   |_   _| |_      _| |_  \ `.___]  | 
#  `.____ .'  `.___.'  |_____|\____| |_____|    |_____|  `._____.'  
# Configurable options                                                                  
@options = {  
  # When a resource has one or more matching tags, the resource will be excluded from the checks
  # and a PASS alert is generated
  # Example:
  # exclude_on_tag: [
  #     {key: "skipped", value: "yeah"},
  #     {key: "skipped", value: "ye*"}
  # ]
  # For wildcard, use *  . If set value: "*", it will match any value inside of the tag
  #
  exclude_on_tag: [
    {key: "environment", value: "demo*"}
  ],

  # Case sensitivity when comparint the tag key & value
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
    c.deep_inspection   = [:vpc_id, :availability_zone, :subnet_name, :route_table_id, :default_route, :routes, :tags]
end

def perform(aws)
  subnets = get_subnets(aws)

  subnets.each do | subnet_id, subnet_info |
    set_data(subnet_info)
    if subnet_info[:default_route] =~ /^igw-/
      if get_tag_matches(@options[:exclude_on_tag],subnet_info[:tags]).count > 0
        pass(message: "Subnet has IGW as default route. Alert set to pass due to exclude_on_tag", resource_id: subnet_id, exclude_on_tag: @options[:exclude_on_tag])
      else
        fail(message: "Subnet has IGW as the default route", resource_id: subnet_id)
      end
    else
      pass(message: "Subnet default route is not IGW", resource_id: subnet_id)
    end

  end
end


#
# Get the list of subnet and their info
#
# Output structure:
# [<subnet_id>].vpc_id
#              .availability_zone
#              .subnet_name
#              .tags
#              .route_table_id
#              .default_route
#              .routes
#
def get_subnets(aws)
  output = {}

  # if a route table is set as Main, the associated subnets are not included.
  # However, vpc_id is included. So, let's create a subnet - vpc_id lookup
  subnets = {}
  aws.ec2.describe_subnets[:subnets].each do | subnet |
    subnet_name = ""

    subnets[subnet[:subnet_id]] = {
      vpc_id: subnet[:vpc_id],
      availability_zone: subnet[:availability_zone],
      subnet_name: subnet_name,
      tags: subnet[:tags]
    }
  end

  route_tables = aws.ec2.describe_route_tables[:route_tables]
  route_tables.each do | route_table |
    default_route = nil

    # Check the default route (ipv4 or ipv6) whether it goes to 
    # IGW or NAT instance, or something else (other)
    route_table[:routes].each do |route|
      if ["0.0.0.0/0","::/0"].include?(route[:destination_cidr_block])
        if route[:gateway_id] =~ /^igw-/
          default_route =  route[:gateway_id]
        elsif route[:network_interface_id] =~ /^eni-/ 
          default_route = route[:network_interface_id]
        else
          default_route = "other"
        end
      end
    end

    route_table[:associations].each do |association|
      # For "main" association, we go through the subnet lookup for matching vpc_id
      # and assign it to the output if the vpc_id matches and there's no explicit association
      if association[:main]
        vpc_id = route_table[:vpc_id]
        subnets.each do | subnet_id, subnet_info |
          # if there is an explicit association, do nothing
          next if output.key?(subnet_id)
          
          if vpc_id == subnet_info[:vpc_id]
            output[subnet_id] = subnets[subnet_id]
            output[subnet_id][:route_table_id] = route_table[:route_table_id]
            output[subnet_id][:default_route] = default_route
            output[subnet_id][:routes] = route_table[:routes]
          end
        end
      # If the association is not main, the subnet is explicitly associated with the route table
      # if the subnet is already added to the output (from the main association), this will override it.
      else
        subnet_id = association[:subnet_id]
        output[subnet_id] = subnets[subnet_id]
        output[subnet_id][:route_table_id] = route_table[:route_table_id]
        output[subnet_id][:default_route] = default_route
        output[subnet_id][:routes] = route_table[:routes]
      end
    end

  end

  return output
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