# CVE Data Analysis Tool

## Overview
The CVE Data Analysis Tool is meticulously crafted to retrieve and scrutinize Common Vulnerabilities and Exposures (CVEs) data from the National Vulnerability Database (NVD).  
It efficiently delivers comprehensive insights, such as the average base score of vulnerabilities, a detailed severity classification, and highlights the top five most affected software packages.  

## Components
- `fetch_cves.py`: Retrieves CVE data from the NVD.  
- `analyze.py`: Analyzes the retrieved CVE data for detailed insights.  
- `Dockerfile`: Facilitates the creation of a Docker container for seamless execution.  
- `requirements.txt`: Enumerates the necessary Python dependencies for the tool.  

## Setup
### Docker (Recommended)
- **Build the Docker image**: Execute `docker build -t <container_name>:<tag> .`
- **Run the container**: Use `docker run -m 512m <container_name>:<tag> --output-directory [output_directory] --days-back [days_back]`
  - Default parameters in Dockerfile: `/tmp` for `output_directory` and `180` for `days_back`.

### Manual Setup
- **Install dependencies**: Run `pip install -r requirements.txt`.
- **Execute scripts**: Use `python fetch_cves.py --output-directory [output_directory] --days-back [days_back]` and `python analyze.py --output-directory [output_directory]`.

## Usage
### fetch_cves.py
- `--output-directory`: Sets the directory to save fetched CVE data.
- `--days-back`: Defines the time frame for fetching data.
- `--verbose`: Enables more detailed logging with prints.
- `--no-analysis`: Opts out of analysis post-data retrieval.

### analyze.py
- `--output-directory`: Specifies the directory containing CVE data for analysis.

## Contributing
Contributions aiming to enhance the functionality of the tool are highly encouraged. Please adhere to the conventional pull request methodology for submitting improvements and use the Black code formatter.
