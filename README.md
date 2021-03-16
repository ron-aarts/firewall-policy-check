# Firewall Policy Check tool

This is one of my earlier scripts that was used to clean up old policies in Juniper Space.<br />
The script was not very efficient or written very nicely (I have sanitized the script so I could post it here). <br />
However, it did end up saving a colleague about 30 hours every month!<br />
This is what got me excited about Network Automation!

#### Table of Contents

1. [Description](#description)
1. [Setup - The basics of getting started with this tool](#setup)
    * [Python](#python)
    * [Required Modules](#required-modules)
1. [Usage](#usage)

## Description

This tool pulls all the firewall policies from all of the firewalls.
It then compares the hit-count against the hit-count that the user entered.<br />
If the policies are older than 90 days and the hit-count does not exceed the 
entered number, the policy will be exported to a Word document.

```diff
- WARNING! THIS TOOL IS NOW ONLY COMPATIBLE WITH PYTHON 3.X!!!
```

## Setup

### Python

This tool requires Python 3.X. <br />
https://www.python.org/downloads/

### Required Modules

This tool uses a few modules that have to be installed seperately with the
following commands from a CMD/PowerShell (as Administrator):<br />
<br />
```
py.exe -3 -m pip install netmiko
py.exe -3 -m pip install docx-mailmerge
py.exe -3 -m pip install python_dateutil
```
## Usage

Unzip to a folder where you have write permissions.<br />
<br />
Put only the policy names of last week's "FW_disable_x_x_x.docx" document in the "IGNORE.txt" file. Every policy name should be on a separate line.<br />
This way the rules that have already been marked for deletion will be ignored by the script.<br />
<br />
Run the "Generate_Report.py" script.<br />
The script will ask you for your TACACS credentials.<br />
Be patient while the script runs and does it work.<br />
If there's a policy with an incorrect date the script will notify you, so it can be fixed in Juniper Space.<br />

When the script is done it will output a Word document in the Output folder, which can be submitted to TRB for approval.<br />
