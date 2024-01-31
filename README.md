# CVE Data Analysis Tool
## Overview
This tool is designed to fetch and analyze data about Common Vulnerabilities and Exposures (CVEs) from the National Vulnerability Database (NVD).  It provides insights such as the average base score of vulnerabilities, severity breakdown, and the top 5 affected packages.

## Components
fetch_cves.py: Fetches CVE data from the NVD.  
analyze.py: Analyzes the fetched CVE data.  
Dockerfile: Sets up a Docker container to run the tool.  
requirements.txt: Lists Python dependencies.  
Setup  
Docker (Recommended)  

Build the Docker image:  ***docker build -t container:tag .<sub>***  
Run the container:  ***docker run container:tag [output_directory] [days_back]***  
You can run with -m 512m to limit memory usage  
_The default parameters set in the Dockerfile are /tmp for output_directory and 180 for days_back_
### Manual Setup

Install dependencies: pip install -r requirements.txt  
Run the scripts directly: python fetch_cves.py [options] and python analyze.py --output-directory [output_directory]  
### Usage
fetch_cves.py  
--output-directory: Specify the directory to save fetched CVE data.  
--days-back: Number of past days to fetch data for.  
--verbose: Enable verbose logging.  
--no-analysis: Skip analysis after fetching data.  
analyze.py  
--output-directory: Directory containing CVE data to analyze.
## Contributing
Contributions to enhance the tool are welcome. Please follow the standard pull request process.
