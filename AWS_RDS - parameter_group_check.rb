#
# Copyright (c) 2013, 2014, 2015, 2016, 2017. Evident.io (Evident). All Rights Reserved. 
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
# Check for RDS instance/cluster parameter group
# 
# Default Conditions:
# - PASS: No offending parameter group setting found
# - FAIL: Found one or more offending parameter group

#    ______     ___     ____  _____   ________   _____     ______   
#  .' ___  |  .'   `.  |_   \|_   _| |_   __  | |_   _|  .' ___  |  
# / .'   \_| /  .-.  \   |   \ | |     | |_ \_|   | |   / .'   \_|  
# | |        | |   | |   | |\ \| |     |  _|      | |   | |   ____  
# \ `.___.'\ \  `-'  /  _| |_\   |_   _| |_      _| |_  \ `.___]  | 
#  `.____ .'  `.___.'  |_____|\____| |_____|    |_____|  `._____.'  
# Configurable options                                                                  
@options = {
  # DB type. Valid values: instance, cluster
  db_type: "instance",

  # List the enforced parameters.
  # db_family is what's shown on AWS console's "Parameter group family" dropdown
  # when you create an new parameter group. 
  # if you put mysql, it will be applied against mysql5.5, mysql5.6, mysql5.7
  # 
  # Format:
  #   enforced_parameters: [
  #     "db_family" => {
  #                      "param1" => value1,
  #                      "param2" => value2,
  #      }
  #   ]
  # 
  # Example:
  # enforced_parameters: {
  #   "mysql" => {
  #      "require_secure_transport" => "1"        
  #   }
  # },
  enforced_parameters: {
    "postgres" => {
      "log_connections" => "1",
      "log_disconnections" => "1",
      "pgaudit.role" => "rds_pgaudit",
      "shared_preload_libraries" => "pgaudit,pg_stat_statements",
      "rds.log_retention_period" => "10080",
      "pgaudit.log" => "role,ddl",
      "rds.force_autovacuum_logging_level" => "log",
      "log_autovacuum_min_duration" => "5000",
      "rds.force_ssl" => "1",
    },
    "aurora-postgres" => {
      "log_connections" => "1",
      "log_disconnections" => "1",
      "pgaudit.role" => "rds_pgaudit",
      "shared_preload_libraries" => "pgaudit,pg_stat_statements",
      "rds.log_retention_period" => "10080",
      "pgaudit.log" => "role,ddl",
    }
  },
}

#    ______   ____  ____   ________     ______   ___  ____     ______   
#  .' ___  | |_   ||   _| |_   __  |  .' ___  | |_  ||_  _|  .' ____ \  
# / .'   \_|   | |__| |     | |_ \_| / .'   \_|   | |_/ /    | (___ \_| 
# | |          |  __  |     |  _| _  | |          |  __'.     _.____`.  
# \ `.___.'\  _| |  | |_   _| |__/ | \ `.___.'\  _| |  \ \_  | \____) | 
#  `.____ .' |____||____| |________|  `.____ .' |____||____|  \______.' 
                                                                      
# deep inspection attribute will be included in each alert
configure do |c|
    c.deep_inspection   = [:group_type ,:group_arn ,:group_family ,:description ,:offending_parameters ,:enforced_parameters]
end

def perform(aws)
  #lowercasing enforced parmeters
  @options[:enforced_parameters] = JSON.parse(JSON.dump(@options[:enforced_parameters], sort_keys=True).downcase)

  if @options[:db_type] == "instance"
    inspect_db_parameter_group_settings(aws)
  elsif @options[:db_type] == "cluster"
    inspect_db_cluster_parameter_group_settings(aws)
  else
    error(message: "Please specify db_type = instance or cluster only")
  end
end


def inspect_db_parameter_group_settings(aws)
  aws.rds.describe_db_parameter_groups[:db_parameter_groups].each do | param_group |
    group_name = param_group[:db_parameter_group_name]
    group_family = param_group[:db_parameter_group_family]
    enforced_family = get_enforced_family(group_family)

    set_data({
      group_type: @options[:db_type],
      group_arn: param_group[:db_parameter_group_arn],
      group_family: group_family,
      description: param_group[:description],
    })

    if enforced_family.nil?
      pass(message: "Parameter group #{group_name} does not have any enforced parameters", resource_id: group_name)
      next
    else
      enforced_parameters = @options[:enforced_parameters][enforced_family]
    end

    offending_parameters = {}

    marker = nil
    while marker != "finish"
      resp = aws.rds.describe_db_parameters(db_parameter_group_name: group_name, marker: marker)
      resp[:parameters].each do | param |
        param_name = param[:parameter_name]
        if enforced_parameters.keys.include?(param_name) and enforced_parameters[param_name] != param[:parameter_value]
          offending_parameters[param_name] = param[:parameter_value]
        end
      end

      if resp[:marker]
        marker = resp[:marker]
      else
        marker = "finish"
      end
    end

    set_data(offending_parameters: offending_parameters, enforced_parameters: enforced_parameters)
    if offending_parameters.count < 1
      pass(message: "Parameter group #{group_name} does not have any offending parameters", resource_id: group_name)
    else
      fail(message: "Parameter group #{group_name} has one or more offending parameters", resource_id: group_name)
    end

  end
end

def inspect_db_cluster_parameter_group_settings(aws)
  aws.rds.describe_db_cluster_parameter_groups[:db_cluster_parameter_groups].each do | param_group |
    group_name = param_group[:db_cluster_parameter_group_name]
    group_family = param_group[:db_parameter_group_family]
    enforced_family = get_enforced_family(group_family)

    set_data({
      group_type: @options[:db_type],
      group_arn: param_group[:db_cluster_parameter_group_arn],
      group_family: group_family,
      description: param_group[:description],
    })

    if enforced_family.nil?
      pass(message: "Parameter group #{group_name} does not have any enforced parameters", resource_id: group_name)
      next
    else
      enforced_parameters = @options[:enforced_parameters][enforced_family]
    end

    offending_parameters = {}

    marker = nil
    while marker != "finish"
      resp = aws.rds.describe_db_cluster_parameters(db_cluster_parameter_group_name: group_name, marker: marker)
      resp[:parameters].each do | param |
        param_name = param[:parameter_name]
        if enforced_parameters.keys.include?(param_name) and enforced_parameters[param_name] != param[:parameter_value]
          offending_parameters[param_name] = param[:parameter_value]
        end
      end

      if resp[:marker]
        marker = resp[:marker]
      else
        marker = "finish"
      end
    end

    set_data(offending_parameters: offending_parameters, enforced_parameters: enforced_parameters)
    if offending_parameters.count < 1
      pass(message: "Parameter group #{group_name} does not have any offending parameters", resource_id: group_name)
    else
      fail(message: "Parameter group #{group_name} has one or more offending parameters", resource_id: group_name)
    end

  end
end


def get_enforced_family(family_name)
  # find the fir
  output = nil

  @options[:enforced_parameters].each do | enforced_family, enforced_parameters |
    return enforced_family if family_name.downcase.start_with?(enforced_family)
  end

  return output
end