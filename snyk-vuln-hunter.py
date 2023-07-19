import subprocess
import sys
import os
from datetime import datetime
import json

def main():
  # Get the parameters from command line arguments
  if len(sys.argv) > 2:
    here = os.getcwd()
    path = sys.argv[1]
    vuln = sys.argv[2]

    if not vuln.startswith(("CVE", "CWE")):
      raise ValueError("CVE or CWE not detected.")
    else:
      print(f'''
 __             _                  _                            _            
/ _\_ __  _   _| | __ /\   /\_   _| |_ __     /\  /\_   _ _ __ | |_ ___ _ __ 
\ \| '_ \| | | | |/ / \ \ / / | | | | '_ \   / /_/ / | | | '_ \| __/ _ \ '__|
_\ \ | | | |_| |   <   \ V /| |_| | | | | | / __  /| |_| | | | | ||  __/ |   
\__/_| |_|\__, |_|\_\   \_/  \__,_|_|_| |_| \/ /_/  \__,_|_| |_|\__\___|_|   
          |___/                                                              

''') 
      hunter = "Hunting for " + vuln + "!"
      bar = "=" * len(hunter)

      print(f'''{bar}''')
      print(f'''{hunter}''')
      print(f'''{bar}\n''')

    timetag = datetime.now().strftime("%Y%m%d%H%M%S")

    use_snyk_os(path, here, vuln, timetag)
    # use_snyk_code(path, here, vuln)

    os.chdir(here)

  else:
    print("Error: Please provide both a path and a string as parameters.", file=sys.stderr)

def use_snyk_os(app_loc, cur_loc, vuln, t):
  try:
    os.chdir(app_loc)
    # command = ['snyk test --json --strict-out-of-sync=false > ', cur_loc, 'snyk-vuln-rep-os-', t, '.json' ]
    command = ['snyk test --json --strict-out-of-sync=false']
    result = subprocess.run(command, capture_output = True, text = True, shell = True)

    # print(result.stdout)

    os_vuln_hunter(json.loads(result.stdout), vuln)

  except FileNotFoundError:
    print("Error: 'snyk' command not found. Please make sure it is installed and added to the system PATH.", file = sys.stderr)

def os_vuln_hunter(data, vuln):
  filtered_data_sets = []

  filtered_data_sets = filter_os_data_set(data, vuln)

  # Print the filtered data sets
  for data_set in filtered_data_sets:
    print(f'''{data_set["id"]}: from package:{data_set["name"]}:{data_set["version"]} and it is upgradeable -> {data_set["isUpgradable"]} from -> {data_set["from"]} upgradepath -> {data_set["upgradePath"]} it is fixed in versions -> {data_set["fixedIn"]}\n''')

def filter_os_data_set(data, vuln):
  clean_data = []

  if vuln.startswith("CWE"):
    for data_set in data["vulnerabilities"]:
      if "identifiers" in data_set:
        # print(data_set["identifiers"])
        if "CWE" in data_set["identifiers"] and vuln in data_set["identifiers"]["CWE"]:
          clean_data.append(data_set)

  if vuln.startswith("CVE"):
    for data_set in data["vulnerabilities"]:
      if "identifiers" in data_set:
        # print(data_set["identifiers"])
        if "CVE" in data_set["identifiers"] and vuln in data_set["identifiers"]["CVE"]:
          clean_data.append(data_set)

  return clean_data

# Running Script
main()