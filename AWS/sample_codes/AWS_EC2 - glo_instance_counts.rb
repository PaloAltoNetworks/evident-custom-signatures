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
# Give instance and node counts for the various services that support instances
#
# glo_instance_counts.rb - John Martinez (john@evident.io)
#
configure do |c|
    c.deep_inspection   = [:ec2_instance_count, :rds_instance_count, :elasticache_node_count, :redshift_node_count, :emr_instance_count]
end

# Required perform method
def perform(aws)

    region = aws.region
    total_count = 0
    
    # count EC2 instances
    ec2_instance_count = aws.ec2.describe_instances.reservations.map(&:instances).count
    total_count += ec2_instance_count
    
    # count RDS DB instances
    rds_instance_count = aws.rds.describe_db_instances.db_instances.count
    total_count += rds_instance_count

    # count ElastiCache nodes
    elasticache_node_count = 0
    aws.ec.describe_cache_clusters.cache_clusters.each do |ec_cluster|
        elasticache_node_count += ec_cluster.cache_nodes.count
    end
    total_count += elasticache_node_count
    
    # count Redshift nodes
    redshift_node_count = 0
    aws.rs.describe_clusters.clusters.each do |rs_cluster|
        redshift_node_count += rs_cluster.cluster_nodes.count
    end
    total_count += redshift_node_count
    
    # count EMR instances
    emr_instance_count = 0
    emr_clusters = aws.emr.list_clusters.clusters
    if emr_clusters.count > 0
        emr_clusters.each do |emr_cluster|
            emr_cluster_id = emr_cluster.id
            emr_instance_count += aws.emr.list_instances(cluster_id: emr_cluster_id).instances.count
        end
    end
    
    set_data(ec2_instance_count: ec2_instance_count, rds_instance_count: rds_instance_count, elasticache_node_count: elasticache_node_count, redshift_node_count: redshift_node_count, emr_instance_count: emr_instance_count)

    if total_count > 0
        warn(message: "Total instance counts in region #{aws.region}: #{total_count}", instance_count: total_count)
    else
        pass(message: "Total instance counts in region #{aws.region} is #{total_count}", instance_count: total_count)
    end

end

