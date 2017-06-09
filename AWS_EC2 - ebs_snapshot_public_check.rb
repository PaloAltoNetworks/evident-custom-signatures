# PROVIDED AS IS WITH NO WARRANTY OR GUARANTEES
# Copyright (c) 2017 Evident.io, Inc., All Rights Reserved
#
# Description:
# Ensure that EBS Snapshot permission is not set to Public
# 
# Default Conditions:
# - PASS: EBS snapshots are not marked as public
# - PASS: EBS snapshot check is skipped. See 'exclude_on_tag'
# - WARN: EBS snapshots are marked as public, but the resource tag matches 'warn_only_on_tag'
# - FAIL: EBS snapshots are marked as public
#
# Resolution/Remediation:
# - Open the Amazon EC2 console at https://console.aws.amazon.com/ec2/.
# - Choose Snapshots in the navigation pane.
# - Select a snapshot and then choose Modify Permissions from the Actions list.
# - Choose Private radio button, or to expose the snapshot to only specific AWS accounts, 
#   choose Private, enter the ID of the AWS account (without hyphens) in the AWS Account Number field, and choose Add Permission. 
#   Repeat until you've added all the required AWS accounts.
#

#    ______     ___     ____  _____   ________   _____     ______   
#  .' ___  |  .'   `.  |_   \|_   _| |_   __  | |_   _|  .' ___  |  
# / .'   \_| /  .-.  \   |   \ | |     | |_ \_|   | |   / .'   \_|  
# | |        | |   | |   | |\ \| |     |  _|      | |   | |   ____  
# \ `.___.'\ \  `-'  /  _| |_\   |_   _| |_      _| |_  \ `.___]  | 
#  `.____ .'  `.___.'  |_____|\____| |_____|    |_____|  `._____.'  
# Configurable options                                                                  
@options = {  
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
    c.deep_inspection   = [:snapshot_id, :volume_alias, :start_time, :description, :volume_size, :encrypted, :tags]
end

def perform(aws)
  # by default, AWS returns both snapshot that you own and snapshots which you have create volume permission (public)
  # This checks only evaluate the snapshots created in this account
  # Per AWS API doc doc reference, if max_results it not specified 
  #           "If this parameter is not used, then DescribeSnapshots returns all results"
  snapshots = aws.ec2.describe_snapshots({owner_ids: ['self']}).snapshots

  public_snapshots = []
  aws.ec2.describe_snapshots({owner_ids: ['self'], restorable_by_user_ids: ['all']})[:snapshots].each do | snapshot |
    public_snapshots.push(snapshot[:snapshot_id])
  end

  snapshots.each do | snapshot |
    snapshot_id = snapshot[:snapshot_id]
    set_data(snapshot)

    if tag_match_found(@options[:exclude_on_tag], snapshot[:tags])
      pass(message: "snapshot #{snapshot_id} is skipped. See excluded_tags for more details", resource_id: snapshot_id , excluded_tags: @options[:exclude_on_tag])
      next
    end

    # If a snapshot is encrypted, it can't be shared. thus, private
    if snapshot[:encrypted]
      pass(message: "snapshot #{snapshot_id} is set to private (due to encryption)", resource_id: snapshot_id)
      next
    end

    if public_snapshots.include?(snapshot_id)
      if tag_match_found(@options[:warn_only_on_tag], snapshot[:tags])
        warn(message: "snapshot #{snapshot_id} permission is set to public. Alert set to warning due to the tags", resource_id: snapshot_id, warn_only_on_tag: @options[:warn_only_on_tag])
      else
        fail(message: "snapshot #{snapshot_id} permission is set to public", resource_id: snapshot_id)
      end
    else
      pass(message: "snapshot #{snapshot_id} is set to private", resource_id: snapshot_id)
    end

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