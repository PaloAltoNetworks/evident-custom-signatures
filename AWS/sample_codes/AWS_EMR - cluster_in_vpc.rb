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
# Check to see if EMR Cluster is deployed in VPC or EC2 classic
# To enforce private VPC, set `fail_on_public_subnet` to true
#
# This custom signature requires additional permission:
# {
#   "Version": "2012-10-17",
#   "Statement": [
#     {
#       "Sid": "EMRInspect",
#       "Effect": "Allow",
#       "Action": [
#         "elasticmapreduce:ListClusters",
#         "elasticmapreduce:DescribeCluster",
#         "elasticmapreduce:DescribeSecurityConfiguration"
#       ],
#       "Resource": [
#         "*"
#       ]
#     }
#   ]
# }
#
# 
# Default Conditions:
# - PASS: EMR cluster is deployed in VPC
# - FAIL: EMR cluster is deployed in EC2 classic
# 
#
# Resolution/Remediation:
# You might need to re-launch the cluster inside of a VPC
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
  #     {key: "environment", value: "demo"},
  #     {key: "environment", value: "dev*"}
  # ]
  # For wildcard, use *  . If set value: "*", it will match any value inside of the tag
  exclude_on_tag: [
  ],

  # Case sensitivity when comparint the tag key & value
  case_insensitive: true,

  # If set to true, EMR cluster is expected to be launched in a private subnet
  fail_on_public_subnet: false

}

#    ______   ____  ____   ________     ______   ___  ____     ______   
#  .' ___  | |_   ||   _| |_   __  |  .' ___  | |_  ||_  _|  .' ____ \  
# / .'   \_|   | |__| |     | |_ \_| / .'   \_|   | |_/ /    | (___ \_| 
# | |          |  __  |     |  _| _  | |          |  __'.     _.____`.  
# \ `.___.'\  _| |  | |_   _| |__/ | \ `.___.'\  _| |  \ \_  | \____) | 
#  `.____ .' |____||____| |________|  `.____ .' |____||____|  \______.' 
                                                                    
# deep inspection attribute will be included in each alert
configure do |c|
  c.deep_inspection   = [:id, :name, :status, :ec2_instance_attributes, :tags, :options, :subnet_details]
end


def perform(aws)
  if @options[:fail_on_public_subnet]
    subnets = get_subnets(aws)
  end

  aws.emr.list_clusters[:clusters].each do | cluster |
    # Terminated EMR cluster stil shows up for ~2 weeks
    next if cluster[:status][:state].include?("TERMINAT")

    cluster_details = aws.emr.describe_cluster(cluster_id: cluster[:id])[:cluster]
    cluster_name = cluster_details[:name]
    set_data(cluster_details)

    if get_tag_matches(@options[:exclude_on_tag], cluster_details[:tags]).count > 0
      pass(message: "EMR cluster #{cluster_name} is excluded due to the tag", resource_id: cluster_details[:id], options: @options)
      next
    end

    if cluster_details[:ec2_instance_attributes].key?("ec2_subnet_id")
      subnet_id = cluster_details[:ec2_instance_attributes][:ec2_subnet_id]
    else
      subnet_id = ""
    end

    if subnet_id == "" or subnet_id == nil
      fail(message: "EMR cluster #{cluster_name} is deployed in EC2 classic", resource_id: cluster_details[:id])
    else
      if @options[:fail_on_public_subnet] == false
        pass(message: "EMR cluster #{cluster_name} is deployed in VPC", resource_id: cluster_details[:id])
      else
        set_data(subnet_details: subnets[subnet_id])
        if subnets[subnet_id][:default_route] =~ /^igw-/
          fail(message: "EMR cluster #{cluster_name} is deployed in VPC's public subnet", resource_id: cluster_details[:id])          
        else
          pass(message: "EMR cluster #{cluster_name} is deployed in VPC's private subnet", resource_id: cluster_details[:id])
        end
      end
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