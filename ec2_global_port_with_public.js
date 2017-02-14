/*
	PROVIDED AS IS WITH NO WARRANTY OR GUARANTEES
	Copyright (c) 2017 Evident.io, Inc., All Rights Reserved

	Description:
	This signature checks the existing Security group against
	the specified IP blacklist (ip_range) and port blacklist (port_blacklists)
	
	Pass if there is no 'offending rule' in SG
	Warn if either:
		- no instance is attached to the SG
		- Attached instance(s) is in private subnet 
	Fail there's at least one offending rule and SG attached to one or more 
	instances in public subnet

	Config:
	ip_range: list of source CIDR to be blacklisted. For any source, 0.0.0.0/0
	port_blacklist: [ {"protocol": "<protocol>", "port": "<port_number>"} ]
		Protocol can be TCP, UDP, or ICMP
		Port:
			- For TCP/UDP:  integer (1-65535)
			- For ICMP: icmp-code, or -1 for all

*/
 
dsl.configure(function(c) {
	c.deep_inspection = ["group_name", "vpc_id", "offending_rules", "ec2_list"];
	c.unique_identifier = ['group_name'];
});

function perform(aws){
	/* _|_|_|    _|_|    _|      _|  _|_|_|_|  _|_|_|    _|_|_|  
	 _|        _|    _|  _|_|    _|  _|          _|    _|        
	 _|        _|    _|  _|  _|  _|  _|_|_|      _|    _|  _|_|  
	 _|        _|    _|  _|    _|_|  _|          _|    _|    _|  
	   _|_|_|    _|_|    _|      _|  _|        _|_|_|    _|_|_|  */
	var ip_range = ["0.0.0.0/0"];
	var port_blacklists = [ {"protocol": "tcp", "port": "22"},
							{"protocol": "tcp", "port": "3389"}
						  ];
	
	// Get Security Group list and EC2 list from AWS
	security_groups = aws.ec2.describe_security_groups().security_groups;
	if (security_groups.length < 1) {
		dsl.pass({message:"No security groups found in this region"});
		return;
	}
	aws_ec2_instances = aws.ec2.describe_instances().reservations;

	// Get subnet details including whether they're public / private
	aws_route_tables = aws.ec2.describe_route_tables().route_tables;
	aws_subnets = aws.ec2.describe_subnets().subnets;
	subnets = get_subnet_details(aws_subnets,aws_route_tables);

	// Compare Security group with the specified blacklist.  
	sg_list = evaluate_security_group(security_groups,ip_range, port_blacklists);
	
	// Get the list of attached EC2 instances to the respective SG
	sg_list = get_attached_ec2(sg_list,aws_ec2_instances);
	
	// Iterate through the security group list for alerting
	Object.keys(sg_list).forEach(function(sg_id){
		// Set data which will be displayed in 'deep_inspection' part of the alert.
		dsl.set_data(sg_list[sg_id]);

		// If Offending rules is found....
		if( sg_list[sg_id].offending_rules.length > 0){
			// Instead of fail, just warn if no EC2 instance is attached
			if(sg_list[sg_id].ec2_list.length === 0){
				dsl.warn({
					message:"Security group "+ sg_list[sg_id].group_name + " has rule violation, but no EC2 instance is attached to it.", 
					resource_id: sg_id,
					blacklist: {ip_range: ip_range, port: port_blacklists} 
					});	
				return;
			}

			// Check to see if any EC2 instance attached to the SG is in public subnet
			var ec2_in_public_subnet = false;
			sg_list[sg_id].ec2_list.forEach(function(ec2_instance){
				if(subnets[ec2_instance.subnet_id].is_public){
					ec2_in_public_subnet = true;
					return;
				} 
			});

			if(ec2_in_public_subnet)
				dsl.fail({
						message:"Security group "+ sg_list[sg_id].group_name + " has rule violation, and attached to at least one EC2 instance on PUBLIC subnet", 
						resource_id: sg_id,
						blacklist: {ip_range: ip_range, portort: port_blacklists} 
						});	
			else
				dsl.warn({
						message:"Security group "+ sg_list[sg_id].group_name + " has rule violation, and attached to at least one EC2 instance on PRIVATE subnet", 
						resource_id: sg_id,
						blacklist: {ip_range: ip_range, port: port_blacklists} 
						});	

		} else {
			// No Offending rules. Pass!
			dsl.pass({
				message:"Security group "+ sg_list[sg_id].group_name + " does not contain any offending rules", 
				resource_id: sg_id,
				blacklist: {ip_range: ip_range, port: port_blacklists} 
				});	
		}
	});
	
}

// Get a list attached EC2 to the security groups
function get_attached_ec2(security_groups,ec2_instances) {
	var output = security_groups;
	// Go through each instance, add the instance ID to security group's ec2_list
	ec2_instances.forEach(function(reservation){
		reservation.instances.forEach(function(instance){
			// Subnet ID will be needed later to determine whether the instannce
			// is in public/private subnet
			var instance_detail = {
				instance_id : instance.instance_id,
				subnet_id : instance.subnet_id
			};
			// Add the instance detail to output[sg.group_id].ec2_list
			instance.security_groups.forEach(function(sg){
				output[sg.group_id].ec2_list.push(instance_detail);
			});
		});
	});
	
	return output;
}

/*
	Evaluate Security group against the blacklist
	Output will be offending SG with respective offending ingress
*/
function evaluate_security_group(security_groups, ip_range_blacklist, port_blacklists){
	var output = {};

	security_groups.forEach(function(security_group){
		var group_id = security_group.group_id;
		var group_details = { group_name: security_group.group_name,
							  vpc_id: security_group.vpc_id,
							  ec2_list: [], 
							  offending_rules: []
		};

		// Iterates through each rule in SG
		security_group.ip_permissions.forEach(function(rule){
			var is_port_blacklisted = false;
			var is_range_blacklisted = false;

			// Check the range to see if it is blacklisted
			rule.ip_ranges.forEach(function(ip_range){
				if(ip_range_blacklist.indexOf(ip_range.cidr_ip) != -1)
					is_range_blacklisted = true;
			});

			// Check the protocol and port to see if it is blacklisted
			port_blacklists.forEach(function(blacklist_detail){
				var protocol = rule.ip_protocol;
				var from_port = Number(rule.from_port);
				var to_port = Number(rule.to_port); 
				var port = Number(blacklist_detail.port);

				// Protocol -1 means all traffic all port
				if(protocol == "-1" && from_port === null & to_port === null){
					is_port_blacklisted = true;
				} 
				else if( protocol == blacklist_detail.protocol){
					if((port >= from_port && port <= to_port) || (protocol == "icmp" && to_port == "-1")){
						is_port_blacklisted = true;
					}
				}
			});


			// Insert the blacklisted rule
			if(is_range_blacklisted && is_port_blacklisted)
				group_details.offending_rules.push(rule);

		});

		output[group_id] = group_details;
	});
	return output;
}


/*
	Return a list of subnet, along with status whether it's a public subnet or private
	Public Subnet has an internet gateway (IGW) attached
	Output: {
			"subnet-id-1": {
				vpc_id: "<vpc_id>",
				is_public: true/false
			}
		}
*/      
function get_subnet_details(subnets,route_tables){
	var result = {};
	subnets.forEach(function(subnet){
		var subnet_id = subnet.subnet_id;
		var vpc_id = subnet.vpc_id;
		var attribs = {vpc_id:vpc_id, is_public:false};

		// Traverse though each route table. Skip if VPC id doesn't match
		route_tables.forEach(function(route_table){
			if(vpc_id != route_table.vpc_id)
				return;

			var any_public_route = false;
			
			//If there is 0.0.0.0/0 to igw, the route table is public
			route_table.routes.forEach(function(route){
				if(route.destination_cidr_block == "0.0.0.0/0" && route.gateway_id.indexOf("igw-") !== -1)
					any_public_route = true;
			});

			// Set the subnet to public if:
			// - public route exist and it's the main route table
			// - public route exists and explicitly associated with the subnet
			route_table.associations.forEach(function(association){
				if(any_public_route === true && (association.main === true || association.subnet_id == subnet_id))
					attribs.is_public = true;
			});
		});

		result[subnet_id] = attribs;
	});

	return result;
}
