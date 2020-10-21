import requests
import json

def hit_api(base_url, http_method, command, auth={}, headers={}, body={}):
    response = {}
    if None in auth.values():
        response['status'] = 'error'
        response['errormessage'] = 'Auth not provided or user / secret is missing'
        return response
    full_path = "/".join([base_url, command])
    if http_method.lower() == "get":
        d9_response = requests.get(url=full_path, auth=(auth['id'], auth['secret']), headers=headers)
    
    if http_method.lower() == "post":
        d9_response = requests.post(url=full_path, auth=(auth['id'], auth['secret']), headers=headers, json=body)
        #requests.post()
    if d9_response.status_code == 200 or d9_response.status_code == 201: # 200 ok or 201 created
        response['data'] = json.loads(d9_response.text)
        response['status'] = 'ok'
    else:
        response['status'] = 'error'
        response['errormessage'] = d9_response.text
        response['errorcode'] = d9_response.status_code
    return response

def process_assets(assets):
    found_assets = []
    for a in assets:
        for af in a['additionalFields']:
            found_asset = {}
            if af['name'] == 'PrivateIpAddress' and af['value'] != '':
                found_asset['entityId'] = a['entityId']
                found_asset['externalCloudAccountId'] = a['externalCloudAccountId']
                found_asset['cloudPlatform'] = a['platform']
                found_asset['PrivateIpAddress'] = af['value']
                found_asset['name'] = a['name']
            if af['name'] == 'PublicIpAddress' and af['value'] != '':
                found_asset['entityId'] = a['entityId']
                found_asset['externalCloudAccountId'] = a['externalCloudAccountId']
                found_asset['cloudPlatform'] = a['platform']
                found_asset['PublicIpAddress'] = af['value']
                found_asset['name'] = a['name']
            if found_asset:
                found_assets.append(found_asset)
    return found_assets

def process_aws_sgs(aws_sgs):
    aws_assets = []
    for aws_sg in aws_sgs['data']: # security group level
        for inbound in aws_sg['services']['inbound']: 
            for scopes in inbound['scope']:
                if scopes['type'] == 'CIDR':
                    aws_asset = {}
                    aws_asset['securityGroupName'] = aws_sg['securityGroupName']
                    aws_asset['cloudAccountId'] = aws_sg['cloudAccountId']
                    aws_asset['externalId'] = aws_sg['externalId']
                    aws_asset['ipAddress'] = scopes['data']['cidr']
                    aws_asset['cloudPlatform'] = "AWS"
                    aws_assets.append(aws_asset)
        #check outbound
        for outbound in aws_sg['services']['outbound']: 
            for scopes in outbound['scope']:
                if scopes['type'] == 'CIDR':
                    aws_asset = {}
                    aws_asset['securityGroupName'] = aws_sg['securityGroupName']
                    aws_asset['cloudAccountId'] = aws_sg['cloudAccountId']
                    aws_asset['externalId'] = aws_sg['externalId']
                    aws_asset['ipAddress'] = scopes['data']['cidr']
                    aws_asset['cloudPlatform'] = "AWS"
                    aws_assets.append(aws_asset)
    return aws_assets

def process_azure_nsgs(azure_nsgs):
    azure_ips = []
    for nsg in azure_nsgs['data']:
        for inbound in nsg['inboundServices']:
            for scope_i in inbound['sourceScopes']:
                if scope_i['type'] == 'CIDR':
                    found_asset = {}
                    found_asset['cloudAccountName'] = nsg['cloudAccountName']
                    found_asset['cloudAccountId'] = nsg['cloudAccountId']
                    found_asset['securityGroupName'] = nsg['name']
                    found_asset['resourceGroupName'] = nsg['resourceGroup']
                    found_asset['ipAddress'] = scope_i['data']['cidr']
                    found_asset['cloudPlatform'] = "Azure"
                    azure_ips.append(found_asset)

            for scope_o in inbound['destinationScopes']:
                if scope_o['type'] == 'CIDR':
                    found_asset = {}
                    found_asset['cloudAccountName'] = nsg['cloudAccountName']
                    found_asset['cloudAccountId'] = nsg['cloudAccountId']
                    found_asset['securityGroupName'] = nsg['name']
                    found_asset['resourceGroupName'] = nsg['resourceGroup']
                    found_asset['ipAddress'] = scope_o['data']['cidr']
                    found_asset['cloudPlatform'] = "Azure"
                    azure_ips.append(found_asset)

        for outbound in nsg['outboundServices']:
            for scope_o in outbound['sourceScopes']:
                if scope_o['type'] == 'CIDR':
                    found_asset = {}
                    found_asset['cloudAccountName'] = nsg['cloudAccountName']
                    found_asset['cloudAccountId'] = nsg['cloudAccountId']
                    found_asset['securityGroupName'] = nsg['name']
                    found_asset['resourceGroupName'] = nsg['resourceGroup']
                    found_asset['ipAddress'] = scope_o['data']['cidr']
                    found_asset['cloudPlatform'] = "Azure"
                    azure_ips.append(found_asset)

            for scope_o in outbound['destinationScopes']:
                if scope_o['type'] == 'CIDR':
                    found_asset = {}
                    found_asset['cloudAccountName'] = nsg['cloudAccountName']
                    found_asset['cloudAccountId'] = nsg['cloudAccountId']
                    found_asset['securityGroupName'] = nsg['name']
                    found_asset['resourceGroupName'] = nsg['resourceGroup']
                    found_asset['ipAddress'] = scope_o['data']['cidr']
                    found_asset['cloudPlatform'] = "Azure"
                    azure_ips.append(found_asset)
    return azure_ips

def process_gcp_ips(gcp_firewall_rules):
    gcp_ips = []
    for rule in gcp_firewall_rules['data']:
        if rule['sourceRanges'] != None:
            for src in rule['sourceRanges']:
                found_asset = {}
                found_asset['cloudAccountId'] = rule['cloudAccountId']
                found_asset['cloudPlatform'] = "GCP"
                found_asset['networkName'] = rule['network']
                found_asset['ipAddress'] = src
                gcp_ips.append(found_asset)
        if rule['destinationRanges'] != None:
            for dst in rule['destinationRanges']:
                found_asset = {}
                found_asset['cloudAccountId'] = rule['cloudAccountId']
                found_asset['cloudPlatform'] = "GCP"
                found_asset['networkName'] = rule['network']
                found_asset['ipAddress'] = dst
                gcp_ips.append(found_asset)
    return gcp_ips

def process_iplist(managed_lists):
    iplist_ips = []
    for li in managed_lists['data']:
        for item in li['items']:
            ip = {}
            ip['ipAddress'] = item['ip']
            ip['comment'] = item['comment']
            ip['cloudPlatform'] = "CloudGuard List"
            ip['name'] = li['name']
            iplist_ips.append(ip)
    return iplist_ips

def process_ip_metadata(ipmetadata):
    ip_metadata_ips = []
    for i in ipmetadata['data']:
        ip = {}
        ip['name'] = i['name']
        ip['ipAddress'] = i['cidr']
        ip['cloudPlatform'] = "CloudGuard IP Classification"
        ip_metadata_ips.append(ip)
    return ip_metadata_ips
