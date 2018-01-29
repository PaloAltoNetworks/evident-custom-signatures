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
# RDS Snapshots that are marked as public.
# 
# Default Conditions:
# - PASS: RDS snapshots are not marked as public
# - PASS: RDS snapshot check is skipped. See 'exclude_on_tag'
# - WARN: RDS snapshots are marked as public, and the resource tag matches 'warn_only_on_tag'
# - FAIL: RDS snapshots are marked as public
#
# Resolution/Remediation:
# To share a manual DB snapshot or DB cluster snapshot by using the Amazon RDS console
# - Sign in to the AWS Management Console and open the Amazon RDS console at https://console.aws.amazon.com/rds/.
# - In the navigation pane, choose Snapshots.
# - For Filter, choose Manual Snapshots.
# - Select the check box for the manual snapshot that you want to share.
# - Choose Snapshot Actions, and then choose Share Snapshot.
# - Choose one of the following options for DB Snapshot Visibility.
# - If the source DB cluster is unencrypted, choose Private to permit only AWS accounts that you specify to restore a DB instance from your manual DB snapshot.
# Warning - If you set DB Snapshot Visibility to Public, all AWS accounts can restore a DB instance from your manual DB snapshot and have access to your data. 
# DO NOT share any manual DB snapshots that contain private information as Public.
# If the source DB cluster is encrypted, DB Snapshot Visibility is set as Private because encrypted snapshots can't be shared as public.
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
  # regular RDS instance snapshot
  include_db_instance_snapshot: true,
  # clustered RDS snapshot    
  include_db_cluster_snapshot: true,     #
  
# EXCLUSION
  # When a resource has one or more matching tags, the resource will be excluded from the checks
  # and an INFO alert is generated
  # Example:
  # exclude_on_tag: [{key: "skipped", value: "yes"}]
  # case insensitive
  exclude_on_tag: [],

# CONDITIONAL
  # When a resource fails the check, resources with matching tags will
  # generate WARN alert instead of FAIL
  # Example:
  # warn_only_on_tag: [
  #         {key: "environment", value: "stage"},
  #         {key: "environment", value: "dev"}
  #]
  warn_only_on_tag: [],
}


#    ______   ____  ____   ________     ______   ___  ____     ______   
#  .' ___  | |_   ||   _| |_   __  |  .' ___  | |_  ||_  _|  .' ____ \  
# / .'   \_|   | |__| |     | |_ \_| / .'   \_|   | |_/ /    | (___ \_| 
# | |          |  __  |     |  _| _  | |          |  __'.     _.____`.  
# \ `.___.'\  _| |  | |_   _| |__/ | \ `.___.'\  _| |  \ \_  | \____) | 
#  `.____ .' |____||____| |________|  `.____ .' |____||____|  \______.' 
                                                                      
# deep inspection attribute will be included in each alert
configure do |c|
    c.deep_inspection   = [:snapshot_identifier, :snapshot_arn, :snapshot_create_time, :snapshot_type, :engine, :vpc_id, :master_username, :is_public, :tags]
end

def perform(aws)
  @snapshots = []
  get_db_snapshots(aws) if @options[:include_db_instance_snapshot]
  get_db_cluster_snapshots(aws) if @options[:include_db_cluster_snapshot]

  @snapshots.each do | snapshot |
    set_data(snapshot)
    snapshot_identifier = snapshot[:snapshot_identifier]
    
    if tag_match_found(@options[:exclude_on_tag], snapshot[:tags])
      pass(message: "snapshot #{snapshot_identifier} is skipped. See excluded_tags for more details", resource_id: snapshot_identifier , excluded_tags: @options[:exclude_on_tag])
      next
    end

    if snapshot.is_public
      if tag_match_found(@options[:warn_only_on_tag], snapshot[:tags])
        warn(message: "snapshot #{snapshot.snapshot_identifier} permission is set to public. Alert set to warning due to the tags", resource_id: snapshot_identifier, warn_only_on_tag: @options[:warn_only_on_tag])
      else
        fail(message: "snapshot #{snapshot.snapshot_identifier} permission is set to public", resource_id: snapshot_identifier)
      end
    else
      pass(message:"snapshot #{snapshot.snapshot_identifier} is not public", resource_id: snapshot_identifier)
    end
  end

end



def get_db_snapshots(aws)
  aws.rds.describe_db_snapshots().db_snapshots.each do | snapshot |
    tmp = {
      snapshot_identifier: snapshot.db_snapshot_identifier,
      snapshot_arn: snapshot.db_snapshot_arn,
      snapshot_create_time: snapshot.snapshot_create_time,
      snapshot_type: snapshot.snapshot_type,
      engine: snapshot.engine,
      vpc_id: snapshot.vpc_id,
      master_username: snapshot.master_username,
      is_public: false
    }

    snapshot_attributes =  aws.rds.describe_db_snapshot_attributes({db_snapshot_identifier: snapshot.db_snapshot_identifier})
    snapshot_attributes.db_snapshot_attributes_result.db_snapshot_attributes.each do | snapshot_attribute |
      # If all is included in the list of values for the restore attribute, then the manual DB cluster snapshot is public
      if snapshot_attribute.attribute_name == 'restore'
        tmp[:is_public] = true if snapshot_attribute.attribute_values[0] == 'all'
      end
    end

    if @options[:exclude_on_tag].count > 0  or  @options[:warn_only_on_tag].count > 0
      tmp[:tags] = aws.rds.list_tags_for_resource({resource_name: snapshot.db_snapshot_arn}).tag_list
    else
      tmp[:tags] = []
    end

    @snapshots.push(tmp)
  end
end

def get_db_cluster_snapshots(aws)
  
  aws.rds.describe_db_cluster_snapshots().db_cluster_snapshots.each do | snapshot |
    tmp = {
      snapshot_identifier: snapshot.db_cluster_snapshot_identifier,
      snapshot_arn: snapshot.db_cluster_snapshot_arn,
      snapshot_create_time: snapshot.snapshot_create_time,
      snapshot_type: snapshot.snapshot_type,
      engine: snapshot.engine,
      vpc_id: snapshot.vpc_id,
      master_username: snapshot.master_username,
      is_public: false
    }

    snapshot_attributes =  aws.rds.describe_db_cluster_snapshot_attributes({db_cluster_snapshot_identifier: snapshot.db_cluster_snapshot_identifier})
    snapshot_attributes.db_cluster_snapshot_attributes_result.db_cluster_snapshot_attributes.each do | snapshot_attribute |
      # If all is included in the list of values for the restore attribute, then the manual DB cluster snapshot is public
      if snapshot_attribute.attribute_name == 'restore'
        tmp[:is_public] = true if snapshot_attribute.attribute_values[0] == 'all'
      end
    end

    if @options[:exclude_on_tag].count > 0  or  @options[:warn_only_on_tag].count > 0
      tmp[:tags] = aws.rds.list_tags_for_resource({resource_name: snapshot.db_cluster_snapshot_arn}).tag_list
    else
      tmp[:tags] = []
    end
    @snapshots.push(tmp)
  end
end


# Return true if one of the tag key-value pair matches
def tag_match_found(option_tags, aws_tags)
  option_tags.each do | option_tag |
    aws_tags.each do | aws_tag | 
      if option_tag[:key].downcase == aws_tag[:key].downcase and option_tag[:value].downcase == aws_tag[:value].downcase
        return true
      end
    end
  end

  return false
end
