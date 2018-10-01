# Description:
# Check Azure Activity Log Archival
# 
# Default Conditions:
# - PASS: Azure Activity Log retention is set to more than 365 days
# - FAIL: Azure Activity log retention is not enabled
# - Fail: Azure Activity Log retention is less than 365 days.
#


#    ______     ___     ____  _____   ________   _____     ______   
#  .' ___  |  .'   `.  |_   \|_   _| |_   __  | |_   _|  .' ___  |  
# / .'   \_| /  .-.  \   |   \ | |     | |_ \_|   | |   / .'   \_|  
# | |        | |   | |   | |\ \| |     |  _|      | |   | |   ____  
# \ `.___.'\ \  `-'  /  _| |_\   |_   _| |_      _| |_  \ `.___]  | 
#  `.____ .'  `.___.'  |_____|\____| |_____|    |_____|  `._____.'  
# Configurable options                                                                  
@options = {
  retention_days: 365
}


#    ______   ____  ____   ________     ______   ___  ____     ______   
#  .' ___  | |_   ||   _| |_   __  |  .' ___  | |_  ||_  _|  .' ____ \  
# / .'   \_|   | |__| |     | |_ \_| / .'   \_|   | |_/ /    | (___ \_| 
# | |          |  __  |     |  _| _  | |          |  __'.     _.____`.  
# \ `.___.'\  _| |  | |_   _| |__/ | \ `.___.'\  _| |  \ \_  | \____) | 
#  `.____ .' |____||____| |________|  `.____ .' |____||____|  \______.' 


# Override the region to global
configure do |c|
  c.display_as = :global
end



def perform(azure)
  profile = azure.monitor.log_profiles.list.value

  if profile.count < 1
    fail(message: "Activity Log export is not enabled on this subscription", resource_id: nil)
  else
    profile = profile[0]
    retention_days = profile.retention_policy.instance_variable_get("@days")
    retention_enabled = profile.retention_policy.instance_variable_get("@enabled")

    alert_attr = {
      id: profile.id,
      name: profile.name,
      storage_account_id: profile.storage_account_id,
      service_bus_rule_id: profile.service_bus_rule_id,
      locations: profile.locations,
      categories: profile.categories,
      retention_days: retention_days,
      retention_enabled: retention_enabled,
      options: @options
    }


    
    if retention_enabled == false
      fail(message: "Activity Log export is not enabled on this subscription", resource_id: profile.name)
    else
      if retention_days == 0 or retention_days > @options[:retention_days]
        pass(message: "Activity Log export is #{retention_days} days", **alert_attr)
      else
        fail(message: "Activity Log export is less than #{@options[:retention_days]} days", **alert_attr)
      end
    end   

  end
end
