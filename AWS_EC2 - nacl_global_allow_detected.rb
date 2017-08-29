# PROVIDED AS IS WITH NO WARRANTY OR GUARANTEES
# Copyright (c) 2017 Evident.io, Inc., All Rights Reserved
#
# Description:
# Global NACL rule detection
# The NACL Rules is open globally if the ip ranges is set to 0.0.0.0/0 (ipv4) or ::/0 (ipv6) and is an ALLOW Rule
#
# Default Conditions:
# - PASS: NACL contains no Global Access ALLOW rules
# - WARN: NACL contains >1 Global Access ALLOW Rule but is unattached to subnets
# - FAIL: NACL contains >1 Global Access ALLOW rule and is attached to subnets
#
# Resolution/Remediation:
# - Sign in to the AWS Management Console and open the Amazon VPC console at https://console.aws.amazon.com/vpc/
# - In the navigation pane, choose Network ACLs
# - Select the nacl, choose 'Inbound' or 'Outbound' tab.
# - Select 'edit'
# - Remove the offending NACL entry by clicking x icon on the right side
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
    { protocol: "tcp", from_port: 0, to_port: 65535},
    { protocol: "udp", from_port: 0, to_port: 65535}
  ],


  # If set to true,
  #   FAIL alert is generated regardless of if the NACL is attached and it contains Global Access ALLOW rule
  # If set to false,
  #   WARN alert is generated if the NACL is unattached and it contains Global Access ALLOW ruleL
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
  c.deep_inspection   = [ :vpc_id, :blacklist, :offending_nacl_details, :tags ]
end


def perform(aws)
  begin
    network_acl = aws.ec2.describe_network_acls[:network_acls]
    network_acl.each do | acl |
        offending_nacls_allow_rules = get_nacl_global_allow_rules(acl[:entries])
        set_data(offending_nacl_details: offending_nacls_allow_rules, blacklist: @options[:blacklist])
        set_data(acl)
        if offending_nacls_allow_rules.count > 0
            if acl[:associations].count > 0
                fail(resource_id: acl[:network_acl_id], message: "Network ACL [#{acl[:network_acl_id]}]  has global allow rule in port range. NACL is attached to >1 subnet.")
            elsif @options[:strict_mode]
                fail(resource_id: acl[:network_acl_id], message: "Network ACL [#{acl[:network_acl_id]}]  has global allow rule in port range. NACL is attached to 0 subnet.")
            else
                warn(resource_id: acl[:network_acl_id], message: "Network ACL [#{acl[:network_acl_id]}]  has global allow rule in port range. NACL is attached to 0 subnet.")
            end
        else
            pass(resource_id: acl[:network_acl_id], message: "Network ACL [#{acl[:network_acl_id]}]  has no global allow rule in port range.")
        end

    end

  rescue StandardError => e
    fail(message: "Error in getting NACL info", error: e.message)
    return
  end


end

def get_nacl_global_allow_rules(acl_entries)
    protocol_number = {
        "tcp" => "6",
        "udp" => "17"

    }
  offending_entries = []
  acl_entries.each do | acl_entry |
      next if acl_entry[:cidr_block] != "0.0.0.0/0" && acl_entry[:ipv_6_cidr_block] != "::/0"
      next if acl_entry[:rule_action] == "deny"
      if acl_entry[:protocol] != "-1"
        no_match=true
        @options[:blacklist].each do | blacklist |
            next if acl_entry[:protocol] !=  protocol_number[blacklist[:protocol].downcase]
            next if acl_entry[:port_range][:from] < blacklist[:from_port] and acl_entry[:port_range][:to] < blacklist[:from_port]
            next if acl_entry[:port_range][:from] > blacklist[:to_port] and acl_entry[:port_range][:to] > blacklist[:to_port]
            no_match=false
            break
        end
        next if no_match
      end
      offending_entries.push(acl_entry)
  end
    return offending_entries
end
