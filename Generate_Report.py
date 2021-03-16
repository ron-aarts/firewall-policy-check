#!/usr/bin/env python

"""
    This tool pulls all the firewall policies from all of the firewalls.
    It then compares the hit-count against the hit-count that the user entered (usually 0).
    If the policies are older than 90 days and the hit-count does not exceed the entered number,
    the policy will be exported to a Word document.
    
"""


from itertools import islice
from datetime import datetime
from netmiko import ConnectHandler
from mailmerge import MailMerge
import dateutil.parser
import getpass
import os
import sys
import re
import random
import time
cwd = os.getcwd()
sys.path.append(cwd)

# Test connection to firewall to prevent script from crashing because of wrong login info.

while True:
    try:
        username = input("\n Username: ")
        passwd = getpass.getpass("\n Password for " + username + ": ")
        Verify_Connection = {
            'device_type': 'juniper',
            'ip': 'x.x.x.x',
            'username': username,
            'password': passwd,
            'port': 22,
            'verbose': False,
        }
        net_connect = ConnectHandler(**Verify_Connection)
        verify = net_connect.find_prompt()[2:-2]
        print("\n Connection successful.")
        net_connect.disconnect()
    except:
        print("\n Unable to connect to the firewalls." 
              " Please verify your credentials and make sure you're connected to the VPN.")
    else:
        net_connect.disconnect()
        break

# Test for hit-count number.

while True:
    try:
        hitcount = int(input('\n Please specify the maximum hit-count of policies to be matched: '))
    except ValueError:
        print('\n Please enter a number!')
    else:
        break

# Ask for number of Word document lines.

while True:
    try:
        word_lines = int(input('\n How many lines maximum should be exported to the Word document: '))
    except ValueError:
        print('\n Please enter a number!')
    else:
        break

# Set the default variables and load the ignore list.

ignore = [line.strip() for line in open('IGNORE.txt', 'r')]
ignore = set(ignore)
default_stdout = sys.stdout
policy_dictionary = {}
hitcount_dictionary = {}
all_v = {}
policies = []
date_formats = ['%m/%d/%Y', '%m/%d/%y']
cur_date = time.strftime("%m-%d-%Y")
date_format_now = "%Y-%m-%d"
date_now = datetime.strptime(str(datetime.now().date()), date_format_now)
config_dictionary = {}
configuration_dictionary = {}
cmd_list = []
output_list = []
commands = []
date_checked = []
export_dictionary = {}
source_addr = []
destination_addr = []
application = []
action = []
description = []
rule = []
hit_count = []
total = []
dedup = set()
total_deduped = []
total_sliced = []

# List all the firewalls.

FW1 = {
    'device_type': 'juniper',
    'ip':   'z.z.z.z',
    'username': username,
    'password': passwd,
    'port': 22,
    'verbose': False
    }

FW2 = {
    'device_type': 'juniper',
    'ip':   'z.z.z.z',
    'username': username,
    'password': passwd,
    'port': 22,
    'verbose': False
    }

FW3 = {
    'device_type': 'juniper',
    'ip':   'z.z.z.z',
    'username': username,
    'password': passwd,
    'port': 22,
    'verbose': False
    }

FW4 = {
    'device_type': 'juniper',
    'ip':   'z.z.z.z',
    'username': username,
    'password': passwd,
    'port': 22,
    'verbose': False
    }

FW5 = {
    'device_type': 'juniper',
    'ip':   'z.z.z.z',
    'username': username,
    'password': passwd,
    'port': 22,
    'verbose': False
    }

FW6 = {
    'device_type': 'juniper',
    'ip':   'z.z.z.z',
    'username': username,
    'password': passwd,
    'port': 22,
    'verbose': False
    }

FW7 = {
    'device_type': 'juniper',
    'ip':   'z.z.z.z',
    'username': username,
    'password': passwd,
    'port': 22,
    'verbose': False
    }

FW8 = {
    'device_type': 'juniper',
    'ip':   'z.z.z.z',
    'username': username,
    'password': passwd,
    'port': 22,
    'verbose': False
}

FW9 = {
    'device_type': 'juniper',
    'ip':   'z.z.z.z',
    'username': username,
    'password': passwd,
    'port': 22,
    'verbose': False
}

FW10 = {
    'device_type': 'juniper',
    'ip':   'z.z.z.z',
    'username': username,
    'password': passwd,
    'port': 22,
    'verbose': False
}

FW11 = {
    'device_type': 'juniper',
    'ip':   'z.z.z.z',
    'username': username,
    'password': passwd,
    'port': 22,
    'verbose': False
}

while True:
    try:
        FW1_or_FW2 = int(input('\n 1. FW1 Firewalls\n 2. FW2 Firewalls\n\n Which firewalls would you like to process '
                              '[1/2]: '))
        if FW1_or_FW2 < 1 or FW1_or_FW2 > 2:
            raise ValueError
    except ValueError:
        print('\n Please enter 1 or 2!')
    else:
        break

if FW1_or_FW2 == 1:
    all_devices = [FW1, FW2, FW3, FW4, FW5, FW6, FW7]
elif FW1_or_FW2 == 2:
    all_devices = [FW8, FW9, FW10, FW11]

# Pick a random firewall to pull the configuration from.

configuration_device = [random.choice(all_devices)]

print('\n Downloading policy hit-counts...')

# Run commands from the commands list on every firewall.

for device in all_devices:
    net_connect = ConnectHandler(**device)
    time.sleep(1)
    hostname_raw = net_connect.find_prompt()
    hostname = re.search(r'@.*', hostname_raw)
    hostname = hostname.group()[1:-1]
    print('\n Downloading hit-counts from: %s.' % hostname)
    output_raw = net_connect.send_command("show security policies hit-count | no-more")
    output_raw = output_raw.split('\n')
    output = []
    for x in output_raw:
        output.append(x[44:])
    output = [x.strip() for x in output]
    while '' in output:
        output.remove('')
    while '------------------------------' in output:
        output.remove('------------------------------')
    while 'Name           Policy count' in output:
        output.remove('Name           Policy count')
    policy_dictionary[hostname] = list(output)
    net_connect.disconnect()

# Split the policy name and hit-count. Put results in all_v dictionary as {Policy_name: hit-count}

for k in list(policy_dictionary.keys()):
    v = policy_dictionary[k]
    for x in v:
        n = (re.search(r' .*$', x).group()).strip()
        x = x[:-len(re.search(r' .*$', x).group())].strip()
        n = int(n)
        if x in all_v:
            all_v[x].append(n)
        else:
            all_v[x] = [n]

# Verify that policy hit-count does not exceed maximum hit-count.
# If the policy hit-count does exceed the maximum hit-count the policy-name (key) will be dropped.

for k, v in list(all_v.items()):
    for x in v:
        if int(x) > hitcount:
            if k in all_v:
                del all_v[k]

# For every policy-name (key) in the all_v dictionary, add the key to the policies list.

for k in list(all_v.keys()):
    policies.append(k)

# If the policy-name exists in the IGNORE.txt, remove it from the policies list.

policies = set(policies)

policies = policies - ignore

# Download policies from devices and create a dictionary from the pulled info.

print('\n Preparing to download the policies. This can take some time depending on the amount of policies.')

if FW1_or_FW2 == 1:
    policy_command = "show configuration security policies global | no-more"
    split_line = '\npol'
elif FW1_or_FW2 == 2:
    policy_command = "show configuration security policies | no-more"
    split_line = '\n    pol'

for device in configuration_device:
    net_connect = ConnectHandler(**device)
    time.sleep(1)
    hostname_raw = net_connect.find_prompt()
    hostname = re.search(r'@.*', hostname_raw)
    hostname = hostname.group()[1:-1]
    print('\n Downloading policies from: %s.' % hostname)
    output = net_connect.send_command(policy_command)
    output = output.split(split_line)
    net_connect.disconnect()
    for x in output:
        if re.search(r'^icy .*{', x):
            k = re.search(r'^icy .*{', x).group()[4:-2]
            v = re.search(r' {4}(description|match)(.*\n.*){4,20}', x).group()
            configuration_dictionary[k] = v

username = ''
passwd = ''

for k, v in list(configuration_dictionary.items()):
    for x in policies:
        if x == k:
            config_dictionary[k] = v

# Remove all keys that have 'Do Not Disable' in the value.
# This will make sure that rules that can't be disabled, won't show up in the list.

for k, v in list(config_dictionary.items()):
    if 'DO NOT DISABLE' in v.upper():
        del config_dictionary[k]

# Verify which policies are older than 90 days. If older than 90 days, the policy names will get appended to
# the date_checked list.

for k, v in list(config_dictionary.items()):
    try:
        if re.search(r'description .*;', v):
            string = re.search(r'description .*;', v).group()
            match = re.findall(r'\d{1,2}[-:\\/.]\d{1,2}[-:\\/.]\d{2,4}', string)
            if len(match) > 1:
                match = match[len(match)-1]
                match = ''.join(match)
                extracted_date = dateutil.parser.parse(match)
                policy_age = date_now - extracted_date
            else:
                match = ''.join(match)
                extracted_date = dateutil.parser.parse(match)
                policy_age = date_now - extracted_date
        else:
            policy_age = date_now - datetime(2000, 1, 1)
    except ValueError:
        print("\n !WARNING!\n Could not find a date for policy with description: ",
              (re.search(r'description .*;', v).group()))
    if policy_age.days >= 90:
        date_checked.append(k)
    if policy_age.days < 0:
        print('\n !WARNING!\n Policy %s has an invalid date. Please correct the date in Space!' % k)

# Remove all the policies that have the keywords listed below in them.

date_checked = [x for x in date_checked if "something1" not in x.upper()]
date_checked = [x for x in date_checked if "something2" not in x.upper()]
date_checked = [x for x in date_checked if "something3" not in x.upper()]
date_checked = [x for x in date_checked if "something4" not in x.upper()]
date_checked = [x for x in date_checked if "something5" not in x.upper()]

# Dedupe date_checked list.
temp_date_checked = []

for x in date_checked:
    if x not in temp_date_checked:
        temp_date_checked.append(x)

date_checked = temp_date_checked

# Create a new dictionary which only has entries that match the date_checked list.

for x in date_checked:
    if x in list(config_dictionary.keys()):
        export_dictionary[x] = config_dictionary[x]

# Generate a list which is exportable to a .docx format.

i = 1
for k, v in list(export_dictionary.items()):
    match_src = re.search(r'source-address.*;', v)
    if match_src:
        source_addr = match_src.group()[15:-1]
    match_dst = re.search(r'destination-address.*;', v)
    if match_dst:
        destination_addr = match_dst.group()[20:-1]
    match_app = re.search(r'application.*;', v)
    if match_app:
        application = match_app.group()[12:-1]
    match_desc = re.search(r'description.*;', v)
    if match_desc:
        description = match_desc.group()[12:-1]
    else:
        description = ''
    if re.search(r'permit;', v):
        action = 'permit'
    elif re.search(r'deny;', v):
        action = 'deny'
    rule = k
    for key, value in list(all_v.items()):
        if k in key:
            hit_count = str(max(value))
    num = i
    output = {'num': str(num),
              'source_addr': source_addr,
              'description': description,
              'rule': rule,
              'application': application,
              'action': action,
              'destination_addr': destination_addr,
              'hit_count': hit_count}
    i += 1
    total.append(output)

# Make sure there are less than word_lines rules in the output Word document.

for x in islice(total, word_lines):
    total_sliced.append(x)

print('\n Creating document from TEMPLATE.docx.')

# Generate Word document with information from the total_sliced dictionary list

template = 'TEMPLATE.docx'
document = MailMerge(template)
document.merge_rows('num', total_sliced)
if FW1_or_FW2 == 1:
    document.write('Output\\FW1_disable %s.docx' % cur_date)
elif FW1_or_FW2 == 2:
    document.write('Output\\FW2_disable %s.docx' % cur_date)

endofscript = input('\n Script complete. Please find the document in the Output folder. '
                        'Press the enter key to exit. \n')
