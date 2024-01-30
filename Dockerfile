# Use a lightweight Python base image
FROM python:3.8-slim
# prevent python from buffering stdout, so that logs can be streamed and viewed in real time
ENV PYTHONUNBUFFERED=1

# Set the working directory
WORKDIR /app

# Copy the script and dependencies file
COPY . /app
RUN chmod +x /app/cve_api/fetch_cves.py

# Install any dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Set the entry point to the script
ENTRYPOINT ["python3", "./cve_api/fetch_cves.py"]

# Set the default arguments
CMD ["/tmp/", "180"]
