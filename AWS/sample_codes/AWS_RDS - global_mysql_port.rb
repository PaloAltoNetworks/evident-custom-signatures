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

#
# Description:
# Check to see if RDS databases (configurable via @db_port)) have their respective
# TCP port open to the world
#
# John Martinez (john@evident.io)

configure do |c|
    c.deep_inspection   = [:vpc_security_groups, :db_name, :db_instance_identifier, :engine, :endpoint, :ip_permission]
    c.unique_identifier = [:rds_name]
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
