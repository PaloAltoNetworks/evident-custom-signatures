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
# Ensure Redshift Clusters are not Publicly Accessible.
# 
# Default Conditions:
#
# - PASS: Cluster is not publicly accessible
# - WARN: The cluster is publicly accessible but the security does not allow for inbound traffic as defined in CONFIG
# - FAIL: The cluster is publicly accessible and the security allows for inbound traffic as defined in CONFIGicly accessible


#
# Remediation:
#
# http://docs.aws.amazon.com/redshift/latest/mgmt/getting-started-cluster-in-vpc.html
#

#    ______     ___     ____  _____   ________   _____     ______   
#  .' ___  |  .'   `.  |_   \|_   _| |_   __  | |_   _|  .' ___  |  
# / .'   \_| /  .-.  \   |   \ | |     | |_ \_|   | |   / .'   \_|  
# | |        | |   | |   | |\ \| |     |  _|      | |   | |   ____  
# \ `.___.'\ \  `-'  /  _| |_\   |_   _| |_      _| |_  \ `.___]  | 
#  `.____ .'  `.___.'  |_____|\____| |_____|    |_____|  `._____.'  
# Configurable options
@options = { 
# RESOURCES TO SCAN
  # Protocol and port pair, separated by dash (-). You can list multiple protocol-port pairs.
  # PASS alert is generated if the security group 
  #   doesn't have any of the protocol-port listed in 'proto_port_list' 
  #   as well as the IP ranges listed in ip_ranges and ipv6_ranges
  #
  # Example:
  #   proto_port_list: ['tcp-22','udp-23']
  #   proto_port_list: ['tcp-*']
  # Use *  for any port number
  proto_port_list: ['tcp-5439'],

  # IP Range to check in CIDR notation
  # Usually, 0.0.0.0/0 represents global access. You can list multiple CIDR blocks
  # Example:
  #   ip_range: ["10.0.0.0/8" , "0.0.0.0/0"]
  ip_ranges: ["0.0.0.0/0"],
  ipv6_ranges: ["::/0"],




}
  
#    ______   ____  ____   ________     ______   ___  ____     ______   
#  .' ___  | |_   ||   _| |_   __  |  .' ___  | |_  ||_  _|  .' ____ \  
# / .'   \_|   | |__| |     | |_ \_| / .'   \_|   | |_/ /    | (___ \_| 
# | |          |  __  |     |  _| _  | |          |  __'.     _.____`.  
# \ `.___.'\  _| |  | |_   _| |__/ | \ `.___.'\  _| |  \ \_  | \____) | 
#  `.____ .' |____||____| |________|  `.____ .' |____||____|  \______.' 
#

configure do |c|
  c.deep_inspection = [:cluster_identifier, :cluster_status, :vpc_id, :publicly_accessible, :region, :vpc_security_group]
end

def perform(aws)
    
  

  clusters = aws.rs.describe_clusters()[:clusters]
  region   = aws.region

  clusters.each do | cluster |
    identifier = cluster[:cluster_identifier]
    status     = cluster[:cluster_status]
    vpc_id     = cluster[:vpc_id]
    is_public  = cluster[:publicly_accessible]
    vpc_security_group = cluster[:vpc_security_groups]
    vpc_security_group_ids = []
    
    vpc_security_group.each do | sg |
        group_id = sg[:vpc_security_group_id]
        vpc_security_group_ids.push(group_id) 
    end
    
    @security_groups = aws.ec2.describe_security_groups({group_ids: vpc_security_group_ids})[:security_groups]
    @offending_sg_ids = []
    @offending_sg_details = {}
    
    inspect_security_groups()
    
    
    set_data(vpc_security_group: @offending_sg_details, cluster_identifier: identifier, cluster_status: status, vpc_id: vpc_id, publicly_accessible: is_public, region: region)
    
    if is_public == true
      fail(message: "Redshift Cluster #{identifier} is publicly accessible.", resource_id: identifier)
    else
      pass(message: "Redshift Cluster #{identifier} is not publicly accessible.", resource_id: identifier)
    end
  end
end

def inspect_security_groups
    @security_groups.each do | sg |
    group_id = sg[:group_id]
    offending_permissions, offending_tcp_ports = find_offending_perm(sg[:ip_permissions])
  
    @offending_sg_ids.push(group_id) if offending_permissions.count > 0
    @offending_sg_details[group_id] = { 
      offending_permissions: offending_permissions,
      offending_tcp_ports: offending_tcp_ports 
    }
    end
end

# inspect the protocol, port, ip ranges
# returns the list of offending rules
# or empty arrays if there is no offending rule
def find_offending_perm(ip_permissions)
  offending_permissions = []
  offending_tcp_ports = []

  ip_permissions.each do | ip_permission |

    @options[:proto_port_list].each do | proto_port|
      pp = proto_port.split('-')

      if ip_permission[:ip_protocol] != "-1"
        next if pp[0].downcase != ip_permission[:ip_protocol].downcase
      end
      
      if  ip_permission[:from_port] != nil && ip_permission[:to_port] != nil && pp[1] != "*"
        next if (pp[1].to_i < ip_permission[:from_port]) ||  (pp[1].to_i > ip_permission[:to_port])
      end

      bad_perm = {
        ip_protocol: ip_permission[:ip_protocol],
        from_port: ip_permission[:from_port],
        to_port: ip_permission[:to_port],
        ip_ranges: [] ,
        ipv_6_ranges: []
      }

      ip_permission[:ip_ranges].each do | ipv4 |
        if @options[:ip_ranges].include? ipv4[:cidr_ip]
          bad_perm[:ip_ranges].push(ipv4[:cidr_ip])
        end
      end

      ip_permission[:ipv_6_ranges].each do | ipv6 |
        if @options[:ipv6_ranges].include? ipv6[:cidr_ipv_6]
          bad_perm[:ipv_6_ranges].push(ipv6[:cidr_ipv_6])
        end
      end

      if bad_perm[:ip_ranges].count > 0 ||  bad_perm[:ipv_6_ranges].count > 0
        offending_permissions.push(bad_perm)
        # Record matching offending tcp port for ELB/NLB check
        if pp[0].downcase == 'tcp' and offending_tcp_ports.include?(pp[1].to_i) == false
          offending_tcp_ports.push(pp[1].to_i) 
        end
      end

    end
  end

  return offending_permissions, offending_tcp_ports
end