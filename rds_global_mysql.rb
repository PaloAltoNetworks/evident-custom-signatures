##
## rds_global_mysql.rb
## Copyright (c) Evident.io, Inc. All rights reserved.
## John Martinez (john@evident.io)
## PROVIDED AS IS WITH NO WARRANTY OR GUARANTEES
##
## Description:
## Check to see if RDS databases (configurable via @db_port)) have their respective
## TCP port open to the world
##

configure do |c|
    c.deep_inspection   = [:vpc_security_groups, :db_name, :db_instance_identifier, :engine, :endpoint, :ip_permission]
end

def perform(aws)
    rds = aws.rds.describe_db_instances.db_instances
    security_group = nil
    sg = nil
    db = nil
    db_name = nil
    db_instance_identifier = nil
    rds_name = nil
    db_engine = nil
    @sg_ingress_rule = []
    @db_port = 3306
    sg_fail_count = 0
    sg_pass_count = 0

    rds.each do |db|
        @database = db
        db_name = db.db_name
        db_instance_identifier = db.db_instance_identifier
        db_sgs = db.vpc_security_groups
        db_engine = db.engine
        
        if db_name == nil
            rds_name = db_instance_identifier
        else
            rds_name = db_name
        end
        
        db_sgs.each do |db_sg|
            sg = db_sg.vpc_security_group_id
            describe_sg = aws.ec2.describe_security_groups({group_ids: [sg]})
            security_groups = describe_sg[:security_groups]
            
            eval = eval_sg(security_groups)

            if eval == "fail"
                sg_fail_count += 1
            elsif eval == "pass"
                sg_pass_count += 1
            end
        end
        set_data(@database, ip_permission: @sg_ingress_rule)
        if sg_fail_count >= 1
            fail(message: "RDS DB #{rds_name} has TCP port #{@db_port} (#{db_engine}) open to the world", resource_id: rds_name)
        else
            pass(message: "RDS DB #{rds_name} does not have TCP port #{@db_port} (#{db_engine}) open to the world", resource_id: rds_name)
        end
    end
    

end

def eval_sg(security_groups)
    security_groups.each do |security_group|
        security_group.ip_permissions.each do |ip_permission|
            to_port = ip_permission[:to_port]
            ip_permission[:ip_ranges].each do |ip_range|
                cidr_ip = ip_range.cidr_ip
                @sg_ingress_rule << ip_permission

                if (ip_permission[:ip_protocol] == 'tcp' && to_port == @db_port && cidr_ip == "0.0.0.0/0")
                    return "fail"
                else
                    return "pass"
                end
            
            end
        end
    end
end
