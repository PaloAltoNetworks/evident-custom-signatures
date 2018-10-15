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
# Ensure VPC security groups utilize approved IP space.
#
# Default Conditions:
#
# - FAIL: Security group contains IP space rule violations
# - WARN: Security group contains IP space rule violations, but has no association 
# - PASS: Security group contains no IP space rule violations
#

# Options
#
@options = {
  # Approved VPC security-group IP ranges
  #  examples:
  #   172.16.8.0/23 = "172.16.8.0/172.16.9.255"
  #   172.16.8.0/24 = "172.16.8.0/172.16.8.255"
  #   172.16.8.0/25 = "172.16.8.0/172.16.8.127"
  #   172.16.8.1/32 = "172.16.8.1/172.16.8.1"
  #
  # Subnet calc that can assist in converting CIDR notation into IP ranges:
  # https://mxtoolbox.com/subnetcalculator.aspx
  #
  approved_cidrs: [
    {
      ip_range: "10.0.0.0/10.0.0.255",
      cidr: "/24"
    },
    {
      ip_range: "10.10.0.0/10.10.255.255",
      cidr: "/16"
    }
  ]
}

configure do |c|
  c.deep_inspection = [:group_id, :group_name, :vpc_id, :offending_rules, :approved_ip_space]
end

def perform(aws)
    
  if @options[:approved_cidrs].nil? or @options[:approved_cidrs].count < 1
    error(message: "The approved_cidrs option is required.")
    return
  end
  
  resp = aws.ec2.describe_security_groups()[:security_groups]

  resp.each do | sg |
    group_id   = sg[:group_id]
    group_name = sg[:group_name]
    vpc_id     = sg[:vpc_id]

    offending_rules = []
    in_use = []
    
    sg[:ip_permissions].each do | perm |
      perm[:ip_ranges].each do | range |
        cidr_ip  = range[:cidr_ip]
        approved = false
      
        @options[:approved_cidrs].each do | cidr |
          first, last = cidr[:ip_range].split("/")
          cidr_class  = cidr[:cidr].split("/").last

          if ip_in_range?(first, last, cidr_ip.split("/").first) and cidr_ip.split("/").last >= cidr_class
            approved = true
          end
        end

        next if approved == true

        sg_data = {
                    ip_protocol: perm[:ip_protocol],
                    from_port:   perm[:from_port],
                    to_port:     perm[:to_port],
                    ip_range:    cidr_ip
                  }

        offending_rules.push(sg_data)

        in_use = aws.ec2.describe_network_interfaces({ filters: [{ name: "group-id", values: [group_id]}] })[:network_interfaces]

      end  
    end

    data = {
             group_id:   group_id,
             group_name: group_name,
             vpc_id:     vpc_id,
             offending_rules:   offending_rules,
             approved_ip_space: @options[:approved_cidrs]
           }

    set_data(data)

    if offending_rules.empty?
      pass(message: "No security group IP space rule violations found.", resource_id: group_id)
    elsif in_use.empty?
      warn(message: "Security group contains IP space rule violations, but has no association.", resource_id: group_id)
    else
      fail(message: "Security group contains IP space rule violations.", resource_id: group_id)
    end
  end
end

# Convert IP addr to a number
#
def ip_to_num(ip)
  ip.split(".").collect{|p| p.rjust(3, "0")}.join.to_i
end

def ip_in_range?(first, last, ip)
  (ip_to_num(first)..ip_to_num(last)).include?(ip_to_num(ip))
end
