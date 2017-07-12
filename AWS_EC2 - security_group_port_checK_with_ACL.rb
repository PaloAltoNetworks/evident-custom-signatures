# PROVIDED AS IS WITH NO WARRANTY OR GUARANTEES
# Copyright (c) 2017 Evident.io, Inc., All Rights Reserved
#
# Description:
# Global Inbound Port Access (SG + ACL)
# The port is open globally if the ip ranges is set to 0.0.0.0/0 (ipv4) or ::/0 (ipv6)
# 
# Default Conditions:
# - PASS: Blacklisted port is not opened globally on both SG and VPC ACL
# - WARN: Blacklisted Port is open globally by SG but NOT open globally on NACL (no explicit ALLOW or has explicit DENY)
# - FAIL: Blacklisted port is open globally on both SG and NACL
#
# Resolution/Remediation:
# - Sign in to the AWS Management Console and open the Amazon EC2 console at https://console.aws.amazon.com/ec2/
# - In the navigation pane, choose Security Group
# - For filter, use the security group ID
# - Select the security group, choose 'Inbound' tab.
# - Select 'edit'
# - Remove the offending security group entry by clicking x icon on the right side 
# - Hit Save
#


#    ______     ___     ____  _____   ________   _____     ______   
#  .' ___  |  .'   `.  |_   \|_   _| |_   __  | |_   _|  .' ___  |  
# / .'   \_| /  .-.  \   |   \ | |     | |_ \_|   | |   / .'   \_|  
# | |        | |   | |   | |\ \| |     |  _|      | |   | |   ____  
# \ `.___.'\ \  `-'  /  _| |_\   |_   _| |_      _| |_  \ `.___]  | 
#  `.____ .'  `.___.'  |_____|\____| |_____|    |_____|  `._____.'  
# Configurable options
@options = { 
  # List of inbound protocol,port,source IP
  # Required parameters:
  # - protocol: "tcp" or "udp"
  # - port_from: 0 - 65535
  # - port_to: 0 - 65535
  #
  # Example:
  # blacklist: [
  #   { protocol: "tcp", from_port: 22, port_to: 22},
  #   { protocol: "tcp", from_port: 0, port_to: 1024}
  # ]
blacklist: [
    { protocol: "tcp", from_port: 3389, to_port: 3389},
    { protocol: "tcp", from_port: 22, to_port: 22}
  ],


  # If set to true,
  #   FAIL alert is generated if the port is open on SG (regardless whether it is blocked by ACL or not)
  # If set to false,
  #   WARN alert is generated if the port is open on SG but blocked by ACL
  strict_mode: false
}


#    ______   ____  ____   ________     ______   ___  ____     ______   
#  .' ___  | |_   ||   _| |_   __  |  .' ___  | |_  ||_  _|  .' ____ \  
# / .'   \_|   | |__| |     | |_ \_| / .'   \_|   | |_/ /    | (___ \_| 
# | |          |  __  |     |  _| _  | |          |  __'.     _.____`.  
# \ `.___.'\  _| |  | |_   _| |__/ | \ `.___.'\  _| |  \ \_  | \____) | 
#  `.____ .' |____||____| |________|  `.____ .' |____||____|  \______.' 
                                                                      
# deep inspection attribute will be included in each alert
configure do |c|
  c.deep_inspection   = [:owner_id, :group_id, :vpc_id, :group_name,
                       :blacklist, :offending_sg_details, :ip_permissions, :tags ]
end


def perform(aws)
  begin

    @network_acl = aws.ec2.describe_network_acls[:network_acls]


    security_groups = aws.ec2.describe_security_groups[:security_groups]
    security_groups.each do | sg |
      vpc_id = sg[:vpc_id]
      
      offending_sg_permissions = find_offending_sg_perm(sg[:ip_permissions], vpc_id)

      set_data(offending_sg_details: offending_sg_permissions, blacklist: @options[:blacklist])
      set_data(sg)

      has_acl_allow = false
      offending_sg_permissions.each do | offending_perm|
        has_acl_allow = true if offending_perm[:nacl_allow_rules] != {}
      end

      if offending_sg_permissions.count > 0 
        if has_acl_allow
          fail(resource_id: sg[:group_id], message: "Security group [#{sg[:group_name]}] has global inbound port. Also allowed by ACL") 
        elsif @options[:strict_mode]
          fail(resource_id: sg[:group_id], message: "Security group [#{sg[:group_name]}] has global inbound port (skipping ACL check)")
        else
          warn(resource_id: sg[:group_id], message: "Security group [#{sg[:group_name]}] has global inbound port, but port is not allowed by ACL")
        end
      else
        pass(resource_id: sg[:group_id], message: "Security group [#{sg[:group_name]}] does not have global inbound port")
      end

    end

  rescue StandardError => e
    fail(message: "Error in getting security groups info", error: e.message)
    return
  end


end

# inspect the protocol, port, ip ranges
# returns the list of offending rules
# or empty array if there is no offending rule
def find_offending_sg_perm(ip_permissions, vpc_id)
  offending_permissions = []

  ip_permissions.each do | ip_permission |

    @options[:blacklist].each do | blacklist |

      if ip_permission[:ip_protocol] != "-1"
        next if blacklist[:protocol].downcase != ip_permission[:ip_protocol].downcase
      end
      
      
      if ip_permission.key?("from_port") && ip_permission.key?("to_port")
        # Next if IP permission range is outside of the blacklisted ports
        next if (ip_permission[:from_port] < blacklist[:from_port] and ip_permission[:to_port] < blacklist[:from_port])
        next if (ip_permission[:from_port] > blacklist[:to_port] and ip_permission[:to_port] > blacklist[:to_port])
      end


      bad_perm = {
        ip_protocol: ip_permission[:ip_protocol],
        from_port: ip_permission[:from_port],
        to_port: ip_permission[:to_port],
        ip_ranges: [] ,
        ipv_6_ranges: [],
      }

      ip_permission[:ip_ranges].each do | ipv4 |
        if ipv4[:cidr_ip] == "0.0.0.0/0"
          bad_perm[:ip_ranges].push(ipv4[:cidr_ip])
        end
      end

      ip_permission[:ipv_6_ranges].each do | ipv6 |
        if ipv6[:cidr_ipv_6] == "::/0"
          bad_perm[:ipv_6_ranges].push(ipv6[:cidr_ipv_6])
        end
      end

      bad_perm[:nacl_allow_rules] = get_nacl_allow_rules(bad_perm, vpc_id)





      offending_permissions.push(bad_perm) if bad_perm[:ip_ranges].count > 0 ||  bad_perm[:ipv_6_ranges].count > 0

    end
  end

  return offending_permissions
end


# Go through each NACL 
# See if there's a NACL rule that allows the IP
def get_nacl_allow_rules(ip_permission, vpc_id)
  output = {}
  protocol_number = {
    "tcp" => "6",
    "udp" => "7"
  }

  [:ip_ranges,:ipv_6_ranges].each do |ipvx|
    next if ip_permission[ipvx].count < 1

    @network_acl.each do | acl |
      next if acl[:vpc_id] != vpc_id

      next if acl[:associations].count < 1

      acl[:entries].each do | acl_entry |
        # skip if outbound rule
        next if acl_entry[:egress]

        if ipvx == :ip_ranges 
          next if acl_entry[:cidr_block] == nil  || acl_entry[:cidr_block] != "0.0.0.0/0" 
        elsif ipvx == :ipv_6_ranges
          next if acl_entry[:ipv_6_cidr_block] == nil || acl_entry[:ipv_6_cidr_block] != "::/0"
        end

        # skip if the protocol number does not math or if it's not -1 (all protocol) 
        if acl_entry[:protocol] != "-1" 
          next if acl_entry[:protocol] !=  protocol_number[ip_permission[:ip_protocol].downcase]
          # no port intersection
          next if acl_entry[:port_range][:from] < ip_permission[:from_port] and acl_entry[:port_range][:to] < ip_permission[:from_port]
          next if acl_entry[:port_range][:from] > ip_permission[:to_port] and acl_entry[:port_range][:to] > ip_permission[:to_port]

          # Reaching this point means that this current ACL entry permits access (partially or completely)
          # No point of evaluating the other entries if the ACL rule is denying a single port 
          break if acl_entry[:rule_action] == "deny" and ip_permission[:from_port] == ip_permission[:to_port]
        end

        # Reaching this point means that this current ACL entry permits access (partially or completely)
        # Process the next ACL entry if the rule is deny  
        next if acl_entry[:rule_action] == "deny"

          
        if output.key?(acl[:network_acl_id])
          output[acl[:network_acl_id]].push(acl_entry)
        else
          output[acl[:network_acl_id]] = [acl_entry]
        end

        # we found the entry that allows the connection. there's no point of continuing further
        break
      end


    end
  end

  return output
end
