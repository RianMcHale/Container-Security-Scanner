FROM python:3.11-slim

# Set the working directory inside the container to /app
WORKDIR /app

# Install basic toosl (curl, bash)
# Download & install Trivy (security scanner)
# Clean up the apt cache afterwards to make the image smaller

RUN apt-get update \
    && apt-get install -y --no-install-recommends curl bash \
    && rm -rf /var/lib/apt/lists/* \
    && curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | bash -s -- -b /usr/local/bin

# Copy the Python dependency list into the container
COPY requirements.txt ./

# Install python packages from requirements.txt
# THe --no-cache-dir flag keeps the image smaller
RUN pip install --no-cache-dir -r requirements.txt

# Copy the Flask application code into the container
COPY app.py ./

# Create a folder outside the container to store the database file
# to ensure no data is lost when container stops
VOLUME ["/data"]

# Sets a default enviroment variable for the Flask app port
ENV PORT=5000

# Tells docker the app will listen on port 5000
EXPOSE 5000

# Start the app :)
CMD ["python", "app.py"]
