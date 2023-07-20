# snyk-vuln-hunter

## Description
Snyk Vuln Hunter is a Python-based CLI tool that filters vulnerabilities based on CWE or CVE numbers. It leverages the Snyk CLI to identify vulnerabilities and provides a targeted approach to vulnerability management by focusing on specified CWE or CVE numbers.

## Group Members
Sean Clarke

## Prerequisites
- Python 3+
- Snyk CLI (Authenticated)
- Linux based operating system

## Getting Started
- Ensure all the prerequisites are met. 
- clone the repo 

### Setup
- No additional setup required.  It is simply a python script.

## Usage

execute the python script passing two parameters as shown below:
```
# <directory of application>: is the location of the codebase you are wishing to evaluate
# <CVE or CWE>: is the EXACT CWE or CVE.  IE. "CWE-601", "CVE-2021-31819", NOT "601" or "CVE202131819"

python3 snyk-vuln-hunter.py "<directory of application>" "<CVE or CWE>"

```

## Features
Easily discover if you have a specific vulnerability your organization needs to address!

## Sample Test
- Use goof repository and search for CWE-601.  There should be an Open Source and Code discovery. 