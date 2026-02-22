FROM python:3.12-slim

WORKDIR /app

# Install dependencies first for Docker layer caching
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Copy source code
COPY pyproject.toml ./
COPY src/ src/

# Include test fixtures for smoke tests with --source sample
COPY tests/fixtures/ tests/fixtures/

# Install the package
RUN pip install --no-cache-dir -e .

ENTRYPOINT ["cad"]
CMD ["report", "--source", "sample", "--format", "json"]
