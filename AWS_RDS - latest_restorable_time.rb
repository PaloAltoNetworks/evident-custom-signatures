# PROVIDED AS IS WITH NO WARRANTY OR GUARANTEES
# Copyright (c) 2017 Evident.io, Inc., All Rights Reserved
#
# Description:
# RDS Latest Restorable Time.  Copy of AWS:RDS-002
# 
# Default Conditions:
# - PASS: RDS latest restorable time is within the specified limit
# - FAIL: RDS latest restorable time is outside of the specified limit
# - FAIL: RDS instance doesn't have latest restorable time.
#
# Resolution/Remediation:
# RDS Restorable Windows are the timeframe to which the latest data is restorable.
# If these windows begin to exceed 5 minutes, then something is generally lagging in the system and could be broken.
# This signature alerts users if the 'latest restorable time' stops working as intended, which increases
# your potential risk if you need to recover data from your backups. Overall, it is expect to see this alert
# switch from PASS to FAIL on occasion with ESP due to transient delays from AWS. If this alert fails
# consistently for one of your accounts, we recommend contacting AWS Support and asking them to take a look.
#
# For more information, AWS has information explaining how the "Latest Restorable Time" impacts your ability to restore a DB instance to a specific point in time
# http://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_PIT.html
#

#    ______     ___     ____  _____   ________   _____     ______   
#  .' ___  |  .'   `.  |_   \|_   _| |_   __  | |_   _|  .' ___  |  
# / .'   \_| /  .-.  \   |   \ | |     | |_ \_|   | |   / .'   \_|  
# | |        | |   | |   | |\ \| |     |  _|      | |   | |   ____  
# \ `.___.'\ \  `-'  /  _| |_\   |_   _| |_      _| |_  \ `.___]  | 
#  `.____ .'  `.___.'  |_____|\____| |_____|    |_____|  `._____.'  
# Configurable options                                                                  
@options = {
# CONDITIONAL
  # Acceptable time difference for last restorable time.  In minutes.
  time_diff: 10,
}


#    ______   ____  ____   ________     ______   ___  ____     ______   
#  .' ___  | |_   ||   _| |_   __  |  .' ___  | |_  ||_  _|  .' ____ \  
# / .'   \_|   | |__| |     | |_ \_| / .'   \_|   | |_/ /    | (___ \_| 
# | |          |  __  |     |  _| _  | |          |  __'.     _.____`.  
# \ `.___.'\  _| |  | |_   _| |__/ | \ `.___.'\  _| |  \ \_  | \____) | 
#  `.____ .' |____||____| |________|  `.____ .' |____||____|  \______.' 
                                                                      
# deep inspection attribute will be included in each alert
configure do |c|
    c.deep_inspection   = [:rds]
end

# Required perform method
def perform(aws)
    now = Time.now.utc
    rds_instances = aws.rds.describe_db_instances()
    
    rds_instances.db_instances.each do |instance|
        set_data(rds: instance)
        
        if instance.latest_restorable_time == nil
            fail(message: "#{instance.db_instance_identifier} #{instance.latest_restorable_time} has no latest restorable date.", resource_id: instance.db_instance_identifier)
            break
        end

        timeDiff = now - instance.latest_restorable_time;
        if timeDiff >= (@options[:time_diff] * 60)
            fail(message: "#{instance.db_instance_identifier}'s latest restorable date is more than #{@options[:time_diff]} minutes ago.", resource_id: instance.db_instance_identifier)
        else
            pass(message: "#{instance.db_instance_identifier}'s latest restorable date is less than #{@options[:time_diff]} minutes ago.", resource_id: instance.db_instance_identifier)
        end
    end
end
