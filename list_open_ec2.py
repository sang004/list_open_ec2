#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Template for python3 terminal scripts.
Script to list out AWS resources with OPEN to world 0.0.0.0/0 ports on security groups
along with ec2 instance id if available
CATEGORY
0 - ok, not resources attached
1 - hmmm, attached to resources
2 - crap, its an EC2, got to investigate
"""

import argparse
import os

import boto3
import json
from datetime import date
import csv
import sys

SCRIPT_NAME = os.path.basename(__file__).replace(".py", "")
OUTDIR = "./OUTPUT_" + SCRIPT_NAME


class SmartFormatter(argparse.HelpFormatter):

    def _split_lines(self, text, width):
        if text.startswith('R|'):
            return text[2:].splitlines()
        # this is the RawTextHelpFormatter._split_lines
        return argparse.HelpFormatter._split_lines(self, text, width)

__author__ = "Ang Shimin"
__credits__ = ["Ang Shimin"]
__license__ = "MIT"
__version__ = "1.0.0"
__maintainer__ = "Ang Shimin"
__email__ = "angsm@gis.a-star.edu.sg"
__status__ = "Development"

parser = argparse.ArgumentParser(
    description='Script list out all AWS IAM permissions of user(s)', formatter_class=SmartFormatter)
group = parser.add_mutually_exclusive_group()

# Optional Arguments
# N.A

args = parser.parse_args()
client_ec2 = boto3.client('ec2')


def print_as_json(dict):
    '''
    outputs json formatted dict onto console
    input: python dictionary
    output: display json on console
    '''

    json_obj = json.dumps(dict, indent=4, default=str)
    print(json_obj)


def get_ec2_tags(instance_id):
    '''
    outputs dictionary with AutoTag_Creator and Name tags
    input: ec2 instance id (i-xxxxxxxxxx)
    output: python dictionary
    '''
    tag_collection = {}

    response = client_ec2.describe_instances(
        InstanceIds=[
            instance_id,
        ]
    )

    if 'Tags' in response['Reservations'][0]['Instances'][0]:
        instance_tags = response['Reservations'][0]['Instances'][0]['Tags']

        for i in instance_tags:
            if i['Key'] == "AutoTag_Creator" or i['Key'] == "Name":
                tag_collection[i['Key']] = i['Value']

    return tag_collection


def get_security_groups():
    '''
    aggregates information into a dictionary
    input: - 
    output: python dictionary
    '''

    response = client_ec2.describe_security_groups()

    return response['SecurityGroups']


def aggregate_information(security_groups, writer):
    '''
    aggregates information into a dictionary, iterates, collects and write row
    input: security group arr and csv writer
    output: N.A last function
    '''

    aggregated_collection = {}
    tag_collection = {}

    for r in security_groups:
        aggregated_collection['group_id'] = r['GroupId']
        print( "READING: ", r['GroupId'] )
        
        attachment_collection = list_network_interfaces(
            aggregated_collection['group_id'])

        # collect info for inbound
        for i in r['IpPermissions']:
            from_port = i['FromPort'] if 'FromPort' in i.keys() else "-"
            to_port = i['ToPort'] if 'ToPort' in i.keys() else "-"
            aggregated_collection['ports'] = ("%s-%s") % (from_port, to_port)

            # increase severity rating using CATEGORY variable
            for c in i['IpRanges']:
                aggregated_collection['ip_range'] = c['CidrIp']
                aggregated_collection['CATEGORY'] = 1 if aggregated_collection['ip_range'] == "0.0.0.0/0" else 0

                if attachment_collection != None:
                    aggregated_collection['CATEGORY'] += 1
                    aggregated_collection.update(attachment_collection)

                    # get EC2 tags if security group appears to be attached to one
                    if 'instance_id' in attachment_collection.keys():
                        tag_collection = get_ec2_tags(
                            attachment_collection['instance_id'])

                if tag_collection:
                    aggregated_collection.update(tag_collection)

                writer.writerow(aggregated_collection)


def list_network_interfaces(security_grp_id):
    '''
    outputs dictionary with network attached resource information
    instance_az, interface_type and Status

    input: security group id (sg-xxxxxxxxxx)
    output: python dictionary
    '''
    instance_id = "-"
    attachment_collection = {}

    response = client_ec2.describe_network_interfaces(
        Filters=[
            {
                'Name': 'group-id',
                'Values': [
                    security_grp_id,
                ]
            },
        ],
        DryRun=False
    )
    
    ## iterate network interfaces as it is an array in documentation
    for n in response['NetworkInterfaces']:

        # if attachement ( there is ec2 )
        if 'Attachment' in n.keys():
            if 'InstanceId' in n['Attachment'].keys():
                attachment_collection['instance_id'] = n['Attachment']['InstanceId']

        attachment_collection['instance_az'] = n['AvailabilityZone']
        attachment_collection['interface_type'] = n['InterfaceType']
        attachment_collection['Status'] = n['Status']

        return attachment_collection


def main():

    today = date.today()
    datenow = today.strftime("%d%b%Y")
    if not os.path.exists(OUTDIR):
        os.mkdir(OUTDIR)

    outfile = open('%s/output_%s_%s.csv' % (OUTDIR, SCRIPT_NAME, datenow), 'w')
    fieldnames = ['CATEGORY', 'group_id', 'ports', 'ip_range', 'instance_id',
                  'instance_az', 'interface_type', 'Status', 'AutoTag_Creator', 'Name']

    writer = csv.DictWriter(outfile, fieldnames=fieldnames)
    writer.writeheader()

    security_groups_arr = get_security_groups()

    aggregate_information(security_groups_arr, writer)
    outfile.close()


if __name__ == '__main__':
    main()
