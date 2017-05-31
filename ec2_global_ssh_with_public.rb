##
## ec2_global_ssh_with_public.rb
## PROVIDED AS IS WITH NO WARRANTY OR GUARANTEES
## Copyright (c) 2015 Evident.io, Inc., All Rights Reserved
##
## Description:
## Globally Accessible Administrative Port -- SSH (TCP/22)
## Also checks if active instances are in a public subnet
##
## Resolution
## This alert triggers when global permission to access TCP port 22 (SSH) is
## detected in a security group. This is dangerous, as it permits the entire
## internet access to connect to port 22 -- usually where a SSH daemon is
## listening. Reducing the permitted IP Addresses or ranges allowed to
## communicate to destination hosts on TCP port 22 is advised. We recommend
## utilizing the static office or home IP addresses of your employees as the
## permitted hosts, or deploying a bastion host with 2-factor authentication
## if this is infeasible. This bastion host is then the only permitted IP to
## communicate with any other nodes inside your account. If you must permit
## global access to TCP port 22 (SSH), then you may suppress this alert.
##
## Note:
## Similar to standard signature AWS:EC2-002
##
configure do |c|
  c.deep_inspection   = [:tags, :owner_id, :group_id, :vpc_id, :group_name,
                       :ip_protocol, :ip_permissions, :ip_permissions_egress,
                       :instance_id]
end

def perform(aws)
  @tcp_ports = %w(22)
  @ranges = ['0.0.0.0/0']
  @security_groups = aws.ec2.describe_security_groups[:security_groups]
  if @security_groups.blank?
    error(message: 'No security groups found in this region')
    return
  end
  @ec2_instances = aws.ec2.describe_instances
  @vpc_subnets = aws.ec2.describe_subnets
  @vpc_route_tables = aws.ec2.describe_route_tables
  @security_group_counter = Hash[@security_groups.map { |security_group| ["#{security_group.group_name}", []] }] # { 'name' => [] }
  add_instances_to_counter
  examine_groups
end

def remove_deleted_security_groups
  @security_groups.reject! { |security_group| security_group.try(:status) == 'ResourceDeleted' }
end

def add_instances_to_counter
  @ec2_instances[:reservations].each do |reservation|
    reservation[:instances].each do |instance|
      instance[:security_groups].each do |security_group|
        next unless @security_group_counter.key? security_group[:group_name]
        @security_group_counter[security_group.group_name] << instance[:instance_id]
      end
    end
  end
end

def examine_groups
  @security_groups.each do |security_group|
    listed_range_found = false
    security_group[:ip_permissions].each do |ip_permission|
      next unless listed_port?(ip_permission)
      @ip_permission = ip_permission
      ip_permission[:ip_ranges].each do |ip_range|
        listed_range_found = listed_range?(ip_range)
        break if listed_range_found
      end
    end
    add_alert(security_group, listed_range_found)
  end
end

def listed_port?(ip_permission)
  (ip_permission[:ip_protocol] == 'tcp' && @tcp_ports.include?(ip_permission[:to_port].to_s))
end

def listed_range?(ip_range)
  @ranges.include?(ip_range[:cidr_ip])
end

def group_instances(security_group)
  @security_group_counter[security_group[:group_name]]
end

def group_instance_details(group_instance_id)
    @ec2_instances[:reservations].each do |reservation|
        reservation[:instances].each do |instance|
            if instance[:instance_id] == group_instance_id
                instance_details = { "instance_id" => instance[:instance_id], "private_ip_address" => instance[:private_ip_address], "public_ip_address" => instance[:public_ip_address],
                                    "vpc_id" => instance[:vpc_id], "subnet_id" => instance[:subnet_id], "instance_tags" => instance[:tags] }
                return instance_details
            end
        end
    end
end

def check_public_subnet(subnet_id)
    route_is_public = false
    subnet_is_public = nil
    @vpc_route_tables[:route_tables].each do |route_table|
        route_table_id = route_table[:route_table_id]
        route_table[:routes].each do |route|
            if route[:destination_cidr_block] == "0.0.0.0/0" && route[:gateway_id] =~ /^igw-/
                route_is_public = true
            end
        end
        route_table[:associations].each do |association|
            if (association[:subnet_id] == subnet_id || association[:main] == true) && route_is_public == true
                subnet_is_public = true
            else
                subnet_is_public = false
            end
        end
        subnet_public = { "subnet_id" => subnet_id, "route_table_id" => route_table_id, "is_public" => subnet_is_public }
        return subnet_public
    end
end

def add_alert(security_group, listed_range_found)
    return if @ip_permission.blank?
    set_data(security_group)

    public_subnet_counter = 0
    if group_instances(security_group).length > 0
        all_group_instances = Array.new
        all_public_subnets = Array.new
        group_instances(security_group).each do |instance_id|
            group_instance_details = group_instance_details(instance_id)
            all_group_instances << group_instance_details
            subnet_id = group_instance_details["subnet_id"]
            check_public_subnet = check_public_subnet(subnet_id)
            all_public_subnets << check_public_subnet
            if check_public_subnet["is_public"] == true && group_instance_details["public_ip_address"] != nil
                public_subnet_counter += 1
            end
        end
        if listed_range_found
            if public_subnet_counter >= 1
                fail(affected_instances: all_group_instances, public_subnets: all_public_subnets, resource_id: security_group[:group_id], message: "Security Group #{security_group[:group_name]} has #{@ip_permission.try(:ip_protocol)} port #{@ip_permission.try(:to_port)} exposed globally.", port: [@ip_permission.try(:to_port), "#{@ip_permission.try(:ip_protocol)}"])
            else
                warn(affected_instances: all_group_instances, public_subnets: all_public_subnets, resource_id: security_group[:group_id], message: "Security Group #{security_group[:group_name]} has #{@ip_permission.try(:ip_protocol)} port #{@ip_permission.try(:to_port)} exposed globally, but subnet or instance is not public.", port: [@ip_permission.try(:to_port), "#{@ip_permission.try(:ip_protocol)}"])
            end
        else
            pass(secure_instances: all_group_instances, resource_id: security_group[:group_id], port: [@ip_permission.try(:to_port), "#{@ip_permission.try(:ip_protocol)}"])
        end
    else
        if listed_range_found
            warn(affected_instances: nil, resource_id: security_group[:group_id], message: "Security Group #{security_group[:group_name]} has #{@ip_permission.try(:ip_protocol)} port #{@ip_permission.try(:to_port)} exposed globally, with no affected instances.", port: [@ip_permission.try(:to_port), "#{@ip_permission.try(:ip_protocol)}"])
        else
            pass(secure_instances: nil, resource_id: security_group[:group_id], port: [@ip_permission.try(:to_port), "#{@ip_permission.try(:ip_protocol)}"])
        end
    end

end

