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

# Description:
# Check Redis at-Rest and in-transit Encryption (currently supported on Redis 3.2.6)
# 
# Default Conditions:
# - PASS: Redis using at-Rest and in-transit encryption
# - FAIL: Redis doesn't have at-Rest and in-transit encryption
# - INFO: Redis cluster doesn't use the engine version that support encryption
# - no alert if cluster type is memcached.
#

#    ______     ___     ____  _____   ________   _____     ______   
#  .' ___  |  .'   `.  |_   \|_   _| |_   __  | |_   _|  .' ___  |  
# / .'   \_| /  .-.  \   |   \ | |     | |_ \_|   | |   / .'   \_|  
# | |        | |   | |   | |\ \| |     |  _|      | |   | |   ____  
# \ `.___.'\ \  `-'  /  _| |_\   |_   _| |_      _| |_  \ `.___]  | 
#  `.____ .'  `.___.'  |_____|\____| |_____|    |_____|  `._____.'  
# Configurable options                                                                  
@options = {
  # As of May 2018, AWS Redis only support encryption on version 3.2.6
  # If there's future supported version, it can be listed here
  # If left empty, all version will be checked 
  #
  # Example: 
  #   check_redis_version: ['3.2.6'],
  #   check_redis_version: ['3.2.6', '3.2.10'],
  check_redis_version: ['3.2.6'],


  # Available options: 'transit_encryption' and 'at_rest_encryption'
  # A fail alert is encryption types specified in this option is not fully satisfied
  check_for: ['transit_encryption', 'at_rest_encryption'],

  # AWS API separates each cluster node as <cluster-name>-<shard-id>-<replication-id>
  # If set to true, the output is grouped by cluster-name
  # similar to how what you see on AWS console.
  group_by_cluster_name: true,


  deep_inspection_fields: [:replication_group_id, :cache_node_type, :engine, :engine_version, 
    :cache_cluster_status, :cache_cluster_create_time, 
    :cache_cluster_id, :cache_subnet_group_name, 
    :transit_encryption_enabled, :at_rest_encryption_enabled
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
    c.deep_inspection   = @options[:deep_inspection_fields]
end


def perform(aws)
  resp = aws.ec.describe_cache_clusters[:cache_clusters]

  clusters = {}
  resp.each do | cache_cluster |

    next if cache_cluster[:engine] == 'memcached'

    cache_cluster_id = cache_cluster[:cache_cluster_id]
    

    # alert per cluster name (similar to AWS console)
    if @options[:group_by_cluster_name]
      replication_group_id = cache_cluster[:replication_group_id]

      if clusters.key?(replication_group_id)
        clusters[replication_group_id][:cluster_nodes].push(cache_cluster_id)
      else 
        clusters[replication_group_id] = {
          cluster_nodes: [cache_cluster_id],
          attributes: {}
        }

        @options[:deep_inspection_fields].each do | field_name |
          if cache_cluster.key?(field_name)
            clusters[replication_group_id][:attributes][field_name] = cache_cluster[field_name]
          end
        end
      end

    # Alert per each cluster ID (based on API)
    else
      send_alert(cache_cluster_id, cache_cluster)      
    end

  end

  if @options[:group_by_cluster_name]
    clusters.each do | cluster_name, cluster_info |
      send_alert(cluster_name, cluster_info[:attributes], cluster_info[:cluster_nodes])
    end
  end
end



def send_alert(cache_cluster_id, cache_cluster, cluster_nodes=[])
  engine_version = cache_cluster[:engine_version]

  set_data(cache_cluster)

  violation = []
  @options[:check_for].each do | attrib |
    violation.push(attrib) if cache_cluster["#{attrib + '_enabled'}".to_sym] == false
  end

  if @options[:check_redis_version].count == 0 or @options[:check_redis_version].include?(engine_version)
    if violation.count > 0
      fail(message: "Cache cluster #{cache_cluster_id} does not have #{violation.join(" and ")} enabled", resource_id: cache_cluster_id, cluster_nodes: cluster_nodes)
    else
      pass(message: "Cache cluster #{cache_cluster_id} has #{@options[:check_for].join(" and ")} enabled", resource_id: cache_cluster_id, cluster_nodes: cluster_nodes)
    end

  else
    info(message: "Chache cluster #{cache_cluster_id} does not support at-rest and in-transit encryption", resource_id: cache_cluster_id, cluster_nodes: cluster_nodes)
  end

  return
end