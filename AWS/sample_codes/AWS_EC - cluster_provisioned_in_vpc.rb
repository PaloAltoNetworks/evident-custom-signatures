# Copyright (c) 2013, 2014, 2015, 2016, 2017, 2018. Evident.io (Evident). All Rights Reserved. 
# 
#   Evident.io shall retain all ownership of all right, title and interest in and to 
#   the Licensed Software, Documentation, Source Code, Object Code, and API's ("Deliverables"), 
#   including (a) all information and technology capable of general application to Evident.io's
#   customers; and (b) any works created by Evident.io prior to its commencement of any
#   Services for Customer.
# 
# Upon receipt of all fees, expenses and taxes due in respect of the relevant Services, 
#   Evident.io grants the Customer a perpetual, royalty-free, non-transferable, license to 
#   use, copy, configure and translate any Deliverable solely for internal business operations
#   of the Customer as they relate to the Evident.io platform and products, and always
#   subject to Evident.io's underlying intellectual property rights.
# 
# IN NO EVENT SHALL EVIDENT.IO BE LIABLE TO ANY PARTY FOR DIRECT, INDIRECT, SPECIAL, 
#   INCIDENTAL, OR CONSEQUENTIAL DAMAGES, INCLUDING LOST PROFITS, ARISING OUT OF 
#   THE USE OF THIS SOFTWARE AND ITS DOCUMENTATION, EVEN IF EVIDENT.IO HAS BEEN HAS BEEN
#   ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
# 
# EVIDENT.IO SPECIFICALLY DISCLAIMS ANY WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
#   THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE. 
#   THE SOFTWARE AND ACCOMPANYING DOCUMENTATION, IF ANY, PROVIDED HEREUNDER IS PROVIDED "AS IS". 
#   EVIDENT.IO HAS NO OBLIGATION TO PROVIDE MAINTENANCE, SUPPORT, UPDATES, ENHANCEMENTS,
#   OR MODIFICATIONS.
# 
# Description:
# Checks if ElastiCache is provisioned within a VPC
#
# Default Conditions:
# - FAIL: if ElastiCache cluster is not provisioned within a VPC (EC2-Classic)
# - PASS: if ElastiCache cluster is provisioned within a VPC
#

@options = {
  # Clusters to ignore
  #
  ignore_list: [
    "demoCluster"
  ]
}

configure do |c|
  c.deep_inspection = [:cluster_id, :cluster_status, :cluster_engine, :cluster_region]
end

def perform(aws)
  resp = aws.ec.describe_cache_clusters()[:cache_clusters]
  region = aws.region

  resp.each do |cluster|
    cluster_id = cluster[:cache_cluster_id]
    cluster_status = cluster[:cache_cluster_status]
    cluster_engine = cluster[:engine]
    cluster_subnet = cluster[:cache_subnet_group_name]

    if @options[:ignore_list].include?(cluster_id)
      pass(message: "Cluster #{cluster_id} is in the ignore list. Skipping check.", resource_id: cluster_id)
      next
    end

    set_data(cluster_id: cluster_id, cluster_status: cluster_status, cluster_engine: cluster_engine, cluster_region: region)

    if cluster_subnet.empty?
      fail(message: "The ElastiCache cluster #{cluster_id} is not provisioned within a VPC.", resource_id: cluster_id)
    else
      pass(message: "The ElastiCache cluster #{cluster_id} is provisioned within a VPC.", resource_id: cluster_id)
    end
  end
end
