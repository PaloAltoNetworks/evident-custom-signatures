# Description:
# Check Azure Activity Log monitored regions
# 
# Default Conditions:
# - PASS: Azure Activity log monitor all enforced regions
# - FAIL: Azure Activity log is not enabled
# - Fail: Azure Activity Log is not monitoring all enforced regions
#

#    ______     ___     ____  _____   ________   _____     ______   
#  .' ___  |  .'   `.  |_   \|_   _| |_   __  | |_   _|  .' ___  |  
# / .'   \_| /  .-.  \   |   \ | |     | |_ \_|   | |   / .'   \_|  
# | |        | |   | |   | |\ \| |     |  _|      | |   | |   ____  
# \ `.___.'\ \  `-'  /  _| |_\   |_   _| |_      _| |_  \ `.___]  | 
#  `.____ .'  `.___.'  |_____|\____| |_____|    |_____|  `._____.'  
# Configurable options                                                                  
@options = {
  # If empty, all regions will be enforced. 
  #
  # Otherwise, a FAIL alert is generated 
  # if one of the enforced region is not monitored
  #
  # Example:
  # enforced_regions: ["westus2","westus"]
  enforced_regions: []
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
  # Get Azure Log Profile Export
  profile = azure.monitor.log_profiles.list.value

  if profile.count < 1
    fail(message: "Activity Log export is not enabled on this subscription", resource_id: nil)
  else
    # As of Oct 2018, there can only be 1 log profile
    profile = profile[0]
    monitored_locations =  profile.locations
    
    if @options[:enforced_regions].count > 0
      enforced_regions = @options[:enforced_regions]
    else
      enforced_regions = ["global"]
      azure.subscriptions.subscriptions.list_locations(azure.subscription_id).value.each do | location |
        enforced_regions.push(location.name)
      end
    end

    alert_attr = {
      id: profile.id,
      name: profile.name,
      storage_account_id: profile.storage_account_id,
      service_bus_rule_id: profile.service_bus_rule_id,
      locations: profile.locations,
      categories: profile.categories,
      unmonitored_locations: (enforced_regions - monitored_locations),
      options: @options
    }

    if alert_attr[:unmonitored_locations].count > 0
      fail(message: "One or more enforced locations are not monitored by the log profile", resource_id: profile.name, **alert_attr)
    else
      pass(message: "Log Profile is configured to monitor all enforced locations", resource_id: profile.name, **alert_attr)
    end

  end
end

