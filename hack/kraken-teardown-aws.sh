#!/bin/bash
#
#
# This script generates a series of commands for removal of clusters. 
#
#   Goal: provide a means of tearing down Kraken clusters *without* access to
#     the configuration files that generated them. 
# 
#   Means:
#     Requires a cluster name specified as command line argument.
#     Queries AWS API, based on the `KubernetesCluster` tag whereever possible.
#     Generates DELETE (equivalent) API calls in the correct order, to remove
#       the cluster from AWS.
#     Should tolerate partially removed clusters in some cases, insofar as 
#       querying their associated elements will simply produce empty sets.
#
#   Limitations:
#     The identification of IAM roles to delete is predicated upon their 
#       reference within the ASG Launch Configurations. If not found, they will 
#       not be removed.
#     The actual DELETE effects are masked by `echo` statements below.
#       The intent is to provide an easy way to validate the operations before execution.
#       To actually execute deletion, simply pipe its output into another bash process.
# 
# See also:
# https://github.com/samsung-cnct/docs/blob/master/cnct/common-tools/Manual%20Deletion%20of%20kraken%20Cluster%20Resources.md
# This script intends to obviate the need for the documentation above. :)

# Exit when a command fails, and when referenced variables are unset.
set -o errexit
set -o pipefail
set -o nounset

# Default: attempt to delete AWS and continue even on failure. 
ALLOW_AWS_ACTION_FAILURE=${ALLOW_AWS_ACTION_FAILURE:-true}

AWS_REGION=${AWS_REGION:-us-east-2}
AWS_COMMON_ARGS="--region=${AWS_REGION} --output=text"
VERBOSE=${VERBOSE:-0}

test "${DEBUG:-0}" -gt 0 && set -x

usage(){
cat <<EOF
  Usage: $0 -c CLUSTER_NAME

  Query AWS API to identify resources related to Kubernetes clusters, identified
  primarily by the "KubernetesCluster" tag having the value CLUSTER_NAME, to be 

  This script generates a series of AWS CLI commands, which should be directly
  executable to tear down the specified Kubernetes cluster, in the correct 
  order.

  To actually execute the teardown, simply pipe this script's output into 
  another bash instance, like so:

    $0 -c CLUSTER_NAME | bash
    
EOF
}

info() {
  [ "${VERBOSE}" -gt 0 ] && echo "# $@" >&2 || return 0
}

fail(){
  echo "[FAIL] $2" >&2
  return $1
}



require_util () {
    which -s "$@" >/dev/null || fail 5 "This script requires utility: $@"
}

dump_state_file () {
  echo "# BEGIN $2 " >&2
  sed 's@^@# @' $1 >&2
  echo "# END $2 " >&2
}

print_command_allow_failure () {
  # Some cases will require that commands are allowed to failed, 
  # e.g. failing to detach a network interface that no longer exists.
  case "${ALLOW_AWS_ACTION_FAILURE}" in
    true) echo "$@ || true" ;;
    *) echo "$@";;
  esac
}

delete_asg () {
  print_command_allow_failure aws ${AWS_COMMON_ARGS} autoscaling delete-auto-scaling-group --auto-scaling-group-name "$1" --force-delete
}

delete_launchconfig () {
  print_command_allow_failure aws ${AWS_COMMON_ARGS} autoscaling delete-launch-configuration --launch-configuration-name "$1"
}

delete_keypair () {
  print_command_allow_failure aws ${AWS_COMMON_ARGS} ec2 delete-key-pair --key-name "$1"
}

delete_instances () {
  [ $# -gt 0 ] || return 0
  print_command_allow_failure aws ${AWS_COMMON_ARGS} ec2 terminate-instances  --instance-ids "$@"
  print_command_allow_failure aws ${AWS_COMMON_ARGS} ec2 wait instance-terminated  --instance-ids "$@"
}

delete_elb (){ 
  print_command_allow_failure aws ${AWS_COMMON_ARGS} elb delete-load-balancer --load-balancer-name "$1"
}

delete_vpc () {
  print_command_allow_failure aws ${AWS_COMMON_ARGS} ec2 delete-vpc --vpc-id "$1"
}

delete_eni () {
  print_command_allow_failure aws ${AWS_COMMON_ARGS} ec2 delete-network-interface  \
    --network-interface-id "$1"
}

detach_eni () {
  print_command_allow_failure aws ${AWS_COMMON_ARGS} ec2 detach-network-interface --attachment-id "$1"
}

wait_for_eni_available () {
  [ $# -eq 0 ] || print_command_allow_failure aws ${AWS_COMMON_ARGS} ec2 wait network-interface-available --network-interface-ids ${@}
}


delete_iam_profile () {
  print_command_allow_failure aws iam delete-instance-profile --instance-profile-name "$1"
}

delete_iam_role () {
  print_command_allow_failure aws iam delete-role --role-name "$1"
}

remove_role_from_instance_profile () {
  print_command_allow_failure aws ${AWS_COMMON_ARGS} iam remove-role-from-instance-profile \
    --instance-profile-name ${2} \
    --role-name ${1}
}

delete_route53_zone () {
  print_command_allow_failure aws ${AWS_COMMON_ARGS} route53 delete-hosted-zone --id "$1"
}

delete_route53_zone_records () {
  local json
  while read json; do
    delete_route53_resource_recordsets $1  "$(printf "'%s'" "${json}")"
  done < <(list_route53_recordsets_for_deletion $1)
}

delete_route53_resource_recordsets () {
  print_command_allow_failure aws ${AWS_COMMON_ARGS} route53 change-resource-record-sets \
    --hosted-zone-id "$1" \
    --change-batch "${2}" \
    --output text --query 'ChangeInfo.Id'
}

delete_subnet_by_id () {
  print_command_allow_failure aws ${AWS_COMMON_ARGS} ec2 delete-subnet  --subnet-id $1
}

delete_security_group_by_id () {
  print_command_allow_failure aws ${AWS_COMMON_ARGS} ec2 delete-security-group --group-id $1
}

delete_security_groups_by_vpc_id () {
  local groupid sgname
  while read groupid _ sgname; do
    case "${sgname}" in
      default) continue ;;
      *) delete_security_group_by_id ${groupid};;
    esac
  done < <(list_security_groups_by_vpc_id $1)
}

delete_subnets_by_vpc_id () {
    local cluster subnetid
    while read cluster subnetid _; do
      delete_subnet_by_id ${subnetid}
    done < <(list_subnet_by_vpc_id "${1}")
}

delete_network_interfaces_by_vpc_id () {
  local attachments_cache=`mktemp /tmp/network_interfaces.XXXXXX`

  list_eni_attachment_state_by_vpc_id $1 > ${attachments_cache}

  # This looping structure attempts to optimize on some parallelism within AWS API.

  while read eni _ subnetid _ status attachid; do
    [ "${status}" == "in-use" ] && detach_eni "${attachid}"
  done < ${attachments_cache}

  # Ensure all the interfaces are unbound/detached/available
  wait_for_eni_available $(awk '{ print $1 }' ${attachments_cache})

  while read eni _ subnetid _ status attachid; do
    delete_eni ${eni}
  done < ${attachments_cache}

  rm ${attachments_cache}
}

delete_route_tables_by_vpc_id () {

  local vpcid routetableid cidrblock ismain attachmentid gatewayid
  local routes_cache=`mktemp /tmp/routes.XXXXXX`

  list_route_tables_by_vpc_id $1 > ${routes_cache}

  dump_state_file ${routes_cache} "Route cache"

  # Detached any already-attached route tables
  while read attachmentid ismain; do
    [ "${attachmentid}" == "null" ] && continue
    [ "${ismain}" == "true" ] && continue
    echo aws ${AWS_COMMON_ARGS} ec2 disassociate-route-table --association-id "${attachmentid}"
  done < <(awk '{ print $6, $5 }' ${routes_cache} | sort -u)

  # Remove routes from the route tables
  while read vpcid routetableid gatewayid cidrblock ismain _ attachmentid; do
    [ "${ismain}" == "true" ] && continue
    [ "${cidrblock}" == "null" ] && continue
    [ "${gatewayid}" == "local" ] && continue
    echo aws ${AWS_COMMON_ARGS} ec2 delete-route --route-table-id "${routetableid}" --destination-cidr-block "${cidrblock}"
  done < <(sort -u ${routes_cache})


  # Remove the actual route table from AWS
  while read routetableid; do
    echo aws ${AWS_COMMON_ARGS} ec2 delete-route-table --route-table-id "${routetableid}"
  done < <(awk '{ print $2 }' ${routes_cache} | sort -u)



  rm ${routes_cache}
}

delete_network_acls_by_vpc_id () {

  local entry_egress aclid rulenum vpcid is_default
  local acl_cache=`mktemp /tmp/networkacls.XXXXXX`

  list_acls_by_vpc_id $1 > ${acl_cache}

  while read rulenum aclid vpcid entry_egress is_default; do
    [ "${rulenum}" -eq 32767 ] && continue
    case ${entry_egress} in
      true)
        echo aws ${AWS_COMMON_ARGS} ec2 delete-network-acl-entry --network-acl-id ${aclid} --egress --rule-number ${rulenum}
        ;;
      false)
        echo aws ${AWS_COMMON_ARGS} ec2 delete-network-acl-entry --network-acl-id ${aclid} --ingress --rule-number ${rulenum}
        ;;
    esac
  done < <(sort -u ${acl_cache})

  while read aclid is_default; do
    [ "${is_default}" == "true" ] && continue
    echo aws ${AWS_COMMON_ARGS} ec2 delete-network-acl --network-acl-id ${aclid}
  done < <(awk '{print $2, $5}' ${acl_cache} | sort -u)

  rm ${acl_cache}
}

detach_and_delete_gateways_by_vpc_id () {
  while read gwid; do
    echo aws ${AWS_COMMON_ARGS} ec2 detach-internet-gateway --internet-gateway-id ${gwid} --vpc-id ${1}
    echo aws ${AWS_COMMON_ARGS} ec2 delete-internet-gateway --internet-gateway-id ${gwid}
  done < <(list_gateways_by_vpc_id $1)
}

describe_cluster_instances () {
  aws ${AWS_COMMON_ARGS} ec2 describe-instances \
    --filter "Name=tag:KubernetesCluster, Values=$1" \
      "Name=instance-state-name, Values=running,stopped,pending,shutting-down" \
    --query="Reservations[*].Instances[*].{a:InstanceId, b:Tags[?Key=='Name']|[0].Value}"
}

describe_launchconfig () {
  aws ${AWS_COMMON_ARGS} autoscaling describe-launch-configurations \
    --launch-configuration-name "$1" \
    --query "LaunchConfigurations[*].{a:LaunchConfigurationName, b:KeyName, c:IamInstanceProfile}"
}

describe_asg () {
  # Produce fields in specific order: GroupName, ARN
  # Columns are ordered alphabetically to their aliases (a and b, here)
  [ $# -gt 0 ] || return 0
  aws ${AWS_COMMON_ARGS} autoscaling describe-auto-scaling-groups \
    --auto-scaling-group-names "${@}" \
    --query 'AutoScalingGroups[*].{a:AutoScalingGroupName, b:AutoScalingGroupARN, c:LaunchConfigurationName}' 
}

list_elb_all () {
  aws ${AWS_COMMON_ARGS} elb describe-load-balancers \
    --query="LoadBalancerDescriptions[*].{a:LoadBalancerName}"
}

list_elb_cluster_tags () {
  [ $# -gt 0 ] || return 0

  print_exec=''
  test "${DEBUG:-0}" -eq 1 && print_exec="-t"

  # This is a pagination hack. LOL.
  echo "${@}" | tr -s ' ' '\n' | xargs ${print_exec} -n 20 -I % \
    aws ${AWS_COMMON_ARGS} elb describe-tags \
    --load-balancer-names % \
    --query="TagDescriptions[*].{a:LoadBalancerName, b:Tags[?Key=='KubernetesCluster']|[0].Value}"
}

list_elb_by_cluster_tag () {
  list_elb_cluster_tags $(list_elb_all) | awk "{ if(\$2 == \"$1\"){ print \$1 } }"
}

list_asg_by_cluster_tag () {
  aws ${AWS_COMMON_ARGS} autoscaling describe-tags \
    --filters "Name=Key, Values=KubernetesCluster" "Name=Value, Values=$1" \
    --query "Tags[*].{a:Value, b:ResourceId, c:ResourceType}" \
      | awk "{ if(\$3 == \"auto-scaling-group\") { print \$2 } }"
}

list_eni_by_vpc_id () {
  aws ${AWS_COMMON_ARGS} ec2 describe-network-interfaces \
    --filter="Name=vpc-id, Values=$1" \
    --query="NetworkInterfaces[].{a:NetworkInterfaceId, b:SubnetId, c:VpcId, d:Status}"
}

list_subnet_by_vpc_id () {
  aws ${AWS_COMMON_ARGS} ec2 describe-subnets \
    --filter="Name=vpc-id, Values=$1" \
    --query="Subnets[].{a:Tags[?Key=='KubernetesCluster']|[0].Value, b:SubnetId, c:VpcId}"
}

list_acls_by_vpc_id () {
  aws --region=${AWS_REGION} ec2 describe-network-acls \
    --filter="Name=vpc-id, Values=$1" \
    --query="NetworkAcls[].{ VpcId:VpcId, NetworkAclId:NetworkAclId, Entries:Entries, IsDefault:IsDefault}" \
      | jq -r '.[] | (.Entries[] | {RuleNumber:.RuleNumber, Egress:.Egress}) + ({NetworkAclId:.NetworkAclId, VpcId:.VpcId, IsDefault:.IsDefault}) | "\(.RuleNumber) \(.NetworkAclId) \(.VpcId) \(.Egress) \(.IsDefault)"'
}

list_route_tables_by_vpc_id () {
  # It's not possible to delete the *main* route table for a given VPC
  # Generates a list of rows with fields: route-table-id, route-cidr-block, association-id
  # Generally each route table will have only one association ID, but probably multiple routes.

  aws --region=us-east-1 --output=json ec2 describe-route-tables \
    --filter 'Name=vpc-id, Values=vpc-2678405e'  \
    --query="RouteTables[]" \
      | jq -r '.[] | {a: .VpcId , b: .RouteTableId} + ((.Associations + [null])[] | {e: .RouteTableAssociationId, d: .Main}) + (.Routes[] | { g: .GatewayId, x: .DestinationCidrBlock })  | "\(.a) \(.b) \(.g) \(.x) \(.d) \(.e)"'
      
}


list_gateways_by_vpc_id () {
  aws ${AWS_COMMON_ARGS} ec2 describe-internet-gateways \
    --filter "Name=attachment.vpc-id, Values=$1" \
    --query="InternetGateways[].{a: InternetGatewayId}"
}

list_security_groups_by_vpc_id () {
  aws ${AWS_COMMON_ARGS} ec2 describe-security-groups \
    --filter="Name=vpc-id, Values=$1" \
    --query="SecurityGroups[].{a:GroupId, b:VpcId, c:GroupName}"
}

list_eni_attachment_state_by_vpc_id () {
  aws ${AWS_COMMON_ARGS} ec2 describe-network-interfaces \
    --query="NetworkInterfaces[].{a:NetworkInterfaceId, b:VpcId, c:SubnetId, d:InterfaceType, e:Status, f:Attachment.AttachmentId}" \
    --filters="Name=vpc-id, Values=$1" 
}

list_vpc_by_cluster_tag () {
  aws ${AWS_COMMON_ARGS} ec2 describe-vpcs \
    --filter "Name=tag:KubernetesCluster, Values=$1" \
    --query="Vpcs[*].{a:VpcId, b:Tags[?Key=='Name']|[0].Value}"
}

list_iam_roles_for_profile () {
  aws ${AWS_COMMON_ARGS} iam get-instance-profile  --instance-profile-name "$1" \
    --query "InstanceProfile.{a:Roles[*]|[0].RoleName, b:InstanceProfileName}"
}

list_route53_zones_by_name () {
  aws ${AWS_COMMON_ARGS} route53 list-hosted-zones \
    --query="HostedZones[*].{b:Id, a:Name}" --max-items=10000 \
      | awk "{ if(\$1 == \"$1\") { print \$2 }}"
}


list_route53_recordsets_for_deletion () {
  # Generate a series of JSON objects for passing into `change-resource-record-sets` to DELETE records.
  aws --region=${AWS_REGION} --output=json route53 list-resource-record-sets \
    --hosted-zone-id "$1" \
    --query="ResourceRecordSets[*].{Type:Type, Name:Name, TTL:TTL, ResourceRecords:ResourceRecords}" \
      | jq -cj '.[] | select(.Type | test("^(NS|SOA)$") | not) | "{\"Changes\":[ { \"Action\":\"DELETE\",\"ResourceRecordSet\": \(.) }]}\n"'
}


# Removes various resources from AWS in the proper order.
delete_cluster_artifacts () {
  # Expects first argument to be the cluster name.
  [ -z "$1" ] && fail 1 "Please specify a cluster name."

  local roles_to_delete keys_to_delete

  roles_to_delete=`mktemp /tmp/delete_roles.XXXXXX`
  keys_to_delete=`mktemp /tmp/delete_keys.XXXXXX`
  
  # Iterate through autoscaling groups for this cluster.
  while read asgname; do
    while read asgname arn lcn; do
      
        # Remove the autoscaling group
        delete_asg ${asgname}
        
        while read lcn kpn iamprofile; do
          # Queue keypair for deletion (if exists)
          echo "${kpn}" >> ${keys_to_delete}
          
          # Queue IAM role  for deletion (if exists)
          echo "${iamprofile}" >> ${roles_to_delete}

          # Remove launch configuration
          delete_launchconfig ${lcn}
        done < <([ -n "${lcn}" ] && describe_launchconfig ${lcn})
    done < <(describe_asg ${asgname})
  done < <(list_asg_by_cluster_tag "$1")
  
  while read kpn; do
    delete_keypair ${kpn}
  done < <(sort ${keys_to_delete} | uniq)

  # Remove remaining EC2 instances
  delete_instances `describe_cluster_instances ${1} | awk '{ print $1 }'`

  # Remove associated load balancers
  while read elb; do
    delete_elb ${elb}
  done < <(list_elb_by_cluster_tag "$1")


  # Remove associated VPC
  while read vpcid vpcName; do

    # Remove associated network interfaces
    delete_network_interfaces_by_vpc_id ${vpcid}

    # Remove associated route tables
    delete_route_tables_by_vpc_id ${vpcid}

    # Remove associated subnets
    # NOTE: this needs to happen AFTER the route tables are removed.
    delete_subnets_by_vpc_id ${vpcid}
    
    # Remove associated gateways
    detach_and_delete_gateways_by_vpc_id ${vpcid}

    # Remove associated network ACLs
    delete_network_acls_by_vpc_id ${vpcid}

    # Remove associated security groups
    delete_security_groups_by_vpc_id ${vpcid}


    # Delete the VPC
    delete_vpc ${vpcid}


  done < <(list_vpc_by_cluster_tag "$1")

  # Remove associated IAM roles
  while read iamprofile; do
    while read role profile; do
      remove_role_from_instance_profile ${role} ${profile}
      delete_iam_role ${role}
      delete_iam_profile ${profile}
    done < <(list_iam_roles_for_profile ${iamprofile})
  done < <(sort ${roles_to_delete} | uniq)

  # Remove zones associated with the cluster
  while read zone; do
    delete_route53_zone_records ${zone}
    delete_route53_zone ${zone}
  done < <(list_route53_zones_by_name "$1.internal.")


  rm  ${roles_to_delete} ${keys_to_delete}
}


require_util jq
require_util awk


main () {
  local CLUSTER_NAME=""

  while builtin getopts ":c:h" OPT "${@}"; do
    case "$OPT" in
      c) CLUSTER_NAME="${OPTARG}" ;;
      h) usage; exit 0 ;;
      \?) fail 1 "-$OPTARG is an invalid option";;
      :) fail 2 "-$OPTARG is missing the required parameter";;
    esac
  done

  if [ -n "${CLUSTER_NAME}" ]; then
    delete_cluster_artifacts "${CLUSTER_NAME}"
  else
    usage
    exit 1
  fi 
}


main "${@:-NONE}"
