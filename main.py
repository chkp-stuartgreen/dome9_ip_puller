import os
import json
import sys
from util import hit_api, process_aws_sgs, process_assets, process_azure_nsgs, process_gcp_ips, process_iplist
from util import process_ip_metadata

# USAGE: The script will pull any metadata from CloudGuard which contains an IP address and write it to a file
# specify the filename as the argument to running the script
# eg "python main.py ipaddresses.json"
# Be sure to set your CloudGuard API key and secret as environment variables before running the script
# (CHKP_CLOUDGUARD_ID and CHKP_CLOUDGUARD_SECRET)

outfile = sys.argv[1]

#API endpoint
dome9_host = "https://api.dome9.com/v2"
auth = {}
auth['id'] = os.getenv('CHKP_CLOUDGUARD_ID')
auth['secret'] = os.getenv('CHKP_CLOUDGUARD_SECRET')

# To cover every IP address, we need to cover three main areas
# Assets
# Security Groups
# IP lists

# Assets
search_body = {}

search_body['pageSize'] = 100
search = hit_api(dome9_host, 'POST', 'protected-asset/search',auth,{}, body=search_body)
assets = search['data']['assets']
if search['data']['searchAfter'] != None:
    # If there's a searchAfter token - need to keep pulling subsequent pages
    search_page_token = search['data']['searchAfter']
    while search['data']['searchAfter']:
        search_body['searchAfter'] = search['data']['searchAfter']
        search = hit_api(dome9_host, 'POST', 'protected-asset/search',auth,{}, body=search_body)
        assets.extend(search['data']['assets'])
processed_assets = process_assets(assets)       

aws_sgs = hit_api(dome9_host, 'GET', 'CloudSecurityGroup', auth)
aws_assets = process_aws_sgs(aws_sgs)

processed_assets.extend(aws_assets)

azure_nsgs = hit_api(dome9_host, 'GET', 'AzureSecurityGroupPolicy', auth)
azure_assets = process_azure_nsgs(azure_nsgs)

processed_assets.extend(azure_assets)

gcp_firewall_rules = hit_api(dome9_host, 'GET', 'GoogleCloudFirewallRule', auth)
gcp_assets = process_gcp_ips(gcp_firewall_rules)

processed_assets.extend(gcp_assets)

managed_lists = hit_api(dome9_host, 'GET', 'ipList', auth )
managed_ips = process_iplist(managed_lists)

processed_assets.extend(managed_ips)

ipmetadata = hit_api(dome9_host, 'GET', 'ipAddressMetadata', auth)
ipmetadata_ips = process_ip_metadata(ipmetadata)

processed_assets.extend(ipmetadata_ips)

with open(outfile, 'w') as f:
    f.write(json.dumps(processed_assets))
