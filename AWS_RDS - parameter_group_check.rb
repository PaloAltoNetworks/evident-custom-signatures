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
# - FAIL: Found one or more violations found. Violations could be any of the following:
#         - instance param group name mismatched
#         - instance parameter group's enforced parameter doesn't match
#         - cluster param group name mismatched
#         - cluster parameter group's enforced parameter doesn't match


#    ______     ___     ____  _____   ________   _____     ______   
#  .' ___  |  .'   `.  |_   \|_   _| |_   __  | |_   _|  .' ___  |  
# / .'   \_| /  .-.  \   |   \ | |     | |_ \_|   | |   / .'   \_|  
# | |        | |   | |   | |\ \| |     |  _|      | |   | |   ____  
# \ `.___.'\ \  `-'  /  _| |_\   |_   _| |_      _| |_  \ `.___]  | 
#  `.____ .'  `.___.'  |_____|\____| |_____|    |_____|  `._____.'  
# Configurable options                                                                  
@options = {
  # List the enforced parameters.
  # 
  # Format:
  # enforced_instance_parameters: [
  #   {
  #     "engine" => String,
  #     "version" => String",
  #     "enforced_parameter_group_name" => nil / String,
  #     "enforced_parameters" => {
  #       String => String,
  #     }
  #   }
  #
  # Note:
  # - "engine":
  #      mysql, postgres, aurora, aurora-postgresql, mssql, etc.
  # - "version":
  #      "*" for all version.
  #      "5.6" will match "5.6.1" and "5.6.2.3"
  # - "enforced_parameter_group_name":
  #      if nil, the parameter group name will not be enforced
  #      Otherwise, the parameter group name will be enforced (case insensitive)
  # - "enforced parameter":
  #      the values are all in String. For example, 
  #         "log_connections" => "1"
  #         "log_autovacuum_min_duration" => "5000"
  #
  # 
  enforced_instance_parameters: [
    {
      "engine" => "postgres",
      "version" => "9.6",
      "enforced_parameter_group_name" => "",
      "enforced_parameters" => {
        "log_connections" => "1",
        "log_disconnections" => "1",
        "pgaudit.role" => "rds_pgaudit",
        "shared_preload_libraries" => "pgaudit,pg_stat_statements",
        "rds.log_retention_period" => "10080",
        "pgaudit.log" => "role,ddl",
        "rds.force_autovacuum_logging_level" => "log",
        "log_autovacuum_min_duration" => "5000",
        "rds.force_ssl" => "1",
      }
    },
    {
      "engine" => "aurora-postgresql",
      "version" => "9.6",
      "enforced_parameter_group_name" => "dbf-aurora-postgresql96",
      "enforced_parameters" => {
        "log_connections" => "1",
        "log_disconnections" => "1",
        "pgaudit.role" => "rds_pgaudit",
        "shared_preload_libraries" => "pgaudit,pg_stat_statements",
        "rds.log_retention_period" => "10080",
        "pgaudit.log" => "role,ddl",
      }
    }
  ],


  enforced_cluster_parameters: [
    {
      "engine" => "aurora-postgresql",
      "version" => "9.6",
      "enforced_parameter_group_name" => "dbf-aurora-postgresql96",
      "enforced_parameters" => {
        "rds.force_autovacuum_logging_level" => "log",
        "log_autovacuum_min_duration" => "5000",
        "rds.force_ssl" => "1"
      }
    }
  ]

}

#    ______   ____  ____   ________     ______   ___  ____     ______   
#  .' ___  | |_   ||   _| |_   __  |  .' ___  | |_  ||_  _|  .' ____ \  
# / .'   \_|   | |__| |     | |_ \_| / .'   \_|   | |_/ /    | (___ \_| 
# | |          |  __  |     |  _| _  | |          |  __'.     _.____`.  
# \ `.___.'\  _| |  | |_   _| |__/ | \ `.___.'\  _| |  \ \_  | \____) | 
#  `.____ .' |____||____| |________|  `.____ .' |____||____|  \______.' 
                                                                      
# deep inspection attribute will be included in each alert
configure do |c|
    c.deep_inspection   = [:db_instance_identifier ,:engine ,:engine_version ,:db_instance_class, :db_parameter_groups, :db_name,
    :db_cluster_identifier, :db_cluster_parameter_group_name, :violations,
    :offending_instance_parameters, :enforced_instance_settings, :offending_cluster_parameters,  :enforced_cluster_settings]
end

def perform(aws)
  @instance_parameter_groups = {}
  @cluster_parameter_groups = {}
  db_instances = aws.rds.describe_db_instances[:db_instances]

  db_instances.each do | db |
    set_data(db)
    violations = []

    db_id = db[:db_instance_identifier]
    param_group_name = db[:db_parameter_groups][0][:db_parameter_group_name]

    # Check for any instance settings' violation
    instance_enforcement_found = false
    @options[:enforced_instance_parameters].each do | enforce |
      # if the engine matches and the version matches, we do the inspection
      if enforce["engine"] == db[:engine] and ( db[:engine_version].include?(enforce["version"]) or enforce["version"] == "*")

        enforced_parameter_group_name = enforce["enforced_parameter_group_name"]
        if enforced_parameter_group_name != nil and enforced_parameter_group_name != param_group_name
          violations.push("Instance parameter group is #{param_group_name}. Expected: #{enforced_parameter_group_name}")
        end

        ## Check the group params
        offending_instance_parameters = get_offending_instance_params(aws, param_group_name, enforce["enforced_parameters"])
        if offending_instance_parameters.count > 0
          violations.push("One or more offending instance parameter found. See 'offending_instance_parameters' for more details")
        end

        set_data(offending_instance_parameters: offending_instance_parameters, enforced_instance_settings: enforce)
        instance_enforcement_found = true
        break
      end
    end

    # Can't find a matching engine / version to enforce the policy
    set_data(enforced_instance_settings: nil) if instance_enforcement_found == false

    # if it's part of a cluster, check for cluster settings
    # check for any cluster violation  
    if db[:db_cluster_identifier].nil? == false
      # Get cluster's param_group_name
      cluster_info = aws.rds.describe_db_clusters(db_cluster_identifier: db[:db_cluster_identifier])[:db_clusters][0]
      param_group_name = cluster_info[:db_cluster_parameter_group]
      set_data(db_cluster_parameter_group_name: param_group_name)
      
      cluster_enforcement_found = false
      @options[:enforced_cluster_parameters].each do | enforce |
        # if the engine matches and the version matches, we do the inspection
        if enforce["engine"] == cluster_info[:engine] and ( cluster_info[:engine_version].include?(enforce["version"]) or enforce["version"] == "*")

          enforced_parameter_group_name = enforce["enforced_parameter_group_name"]
          if enforced_parameter_group_name != nil and enforced_parameter_group_name != param_group_name
            violations.push("Cluster parameter group is #{param_group_name}. Expected: #{enforced_parameter_group_name}")
          end

          ## Check the group params
          offending_cluster_parameters = get_offending_cluster_params(aws, param_group_name, enforce["enforced_parameters"])
          if offending_cluster_parameters.count > 0
            violations.push("One or more offending cluster parameter found. See 'offending_cluster_parameters' for more details")
          end

          set_data(offending_cluster_parameters: offending_cluster_parameters, enforced_cluster_settings: enforce)
          break
        end
      end
    end

    # Can't find a matching engine / version to enforce the policy
    set_data(enforced_cluster_settings: nil) if cluster_enforcement_found == false

    set_data(violations: violations)
    if violations.count > 0
      fail(message: "DB instance #{db_id} has one or more violations", resource_id: db_id)
    else
      pass(message: "DB instance #{db_id} does not have any violations", resource_id: db_id)
    end

  end
end

############################################################
# Iterate through instance parameters
# Cache the instance parameters to save API calls
#
# return offending parameters
############################################################
def get_offending_instance_params(aws, param_group_name, enforced_parameters)
  instance_parameters = []

  if @instance_parameter_groups.key?(param_group_name)
    instance_parameters = @instance_parameter_groups[param_group_name]
  else
    # Grab DB parameters
    marker = nil
    while marker != "finish"
      resp = aws.rds.describe_db_parameters(db_parameter_group_name: param_group_name, marker: marker)
      resp[:parameters].each do | param |
        instance_parameters.push(param)
      end

      if resp[:marker]
        marker = resp[:marker]
      else
        marker = "finish"
      end
    end

    ## cache it to save API calls
    @instance_parameter_groups[param_group_name] = instance_parameters
  end

  offending_parameters = {}
  instance_parameters.each do | param |
    param_name = param[:parameter_name]
    if enforced_parameters.keys.include?(param_name) and enforced_parameters[param_name] != param[:parameter_value]
      offending_parameters[param_name] = param[:parameter_value]
    end
  end

  return offending_parameters
end


############################################################
# Iterate through cluster parameters
# Cache the cluster parameters to save API calls
#
# return offending parameters
############################################################
def get_offending_cluster_params(aws, param_group_name, enforced_parameters)
  cluster_parameters = []

  if @cluster_parameter_groups.key?(param_group_name)
    cluster_parameters = @cluster_parameter_groups[param_group_name]
  else
    # Grab DB parameters
    marker = nil
    while marker != "finish"
      resp = aws.rds.describe_db_cluster_parameters(db_cluster_parameter_group_name: param_group_name, marker: marker)
      resp[:parameters].each do | param |
        cluster_parameters.push(param)
      end

      if resp[:marker]
        marker = resp[:marker]
      else
        marker = "finish"
      end
    end

    ## cache it to save API calls
    @cluster_parameter_groups[param_group_name] = cluster_parameters
  end

  offending_parameters = {}
  cluster_parameters.each do | param |
    param_name = param[:parameter_name]
    if enforced_parameters.keys.include?(param_name) and enforced_parameters[param_name] != param[:parameter_value]
      offending_parameters[param_name] = param[:parameter_value]
    end
  end

  return offending_parameters
end