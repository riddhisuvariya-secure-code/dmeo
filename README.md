# SBOM Job Scripts

This repository contains job scripts for syncing package metadata from PyPI, Maven Central, and Go modules to MongoDB. The scripts calculate SHA hashes to detect changes and only update when package metadata has changed.

## Prerequisites

- Python 3.11+
- Docker and Docker Compose
- pip

## Setup

### 1. Install Python Dependencies

```bash
pip install -r requirements.txt
```

### 2. Start MongoDB with Docker Compose

Start MongoDB in a Docker container:

```bash
docker-compose up -d
```

This will:
- Start MongoDB on port 27017
- Create a persistent data volume at `./mongodb_data`
- Run health checks to ensure MongoDB is ready

To stop MongoDB:

```bash
docker-compose down
```

To view MongoDB logs:

```bash
docker-compose logs -f mongodb
```

### 3. Configure Environment Variables (Optional)

The scripts use environment variables for MongoDB configuration. By default, they connect to `mongodb://localhost:27017/` with database name `sbom_test`.

To customize the connection:

1. Copy the example environment file:
   ```bash
   cp .env.example .env
   ```

2. Edit `.env` with your MongoDB settings:
   ```env
   MONGO_URI=mongodb://localhost:27017/
   MONGO_DB_NAME=sbom_test
   ```

If you don't create a `.env` file, the scripts will use the default values (backward compatible).

## Connecting from Other Folders (Same VM)

Since MongoDB is running on `localhost:27017`, you can connect to it from **any folder on the same VM**. Here's how:

### Option 1: Using Environment Variables (Recommended)

In your other folder/project, create a `.env` file with:

```env
MONGO_URI=mongodb://localhost:27017/
MONGO_DB_NAME=sbom_test
```

Then in your Python code:

```python
import os
from dotenv import load_dotenv
import pymongo

# Load environment variables
load_dotenv()

# Connect to MongoDB
MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017/")
DB_NAME = os.getenv("MONGO_DB_NAME", "sbom_test")

client = pymongo.MongoClient(MONGO_URI)
db = client[DB_NAME]

# Access collections
pypi_collection = db["Updated_pypi_metadata"]
maven_collection = db["Updated_maven_metadata"]
go_collection = db["Updated_go_metadata"]
```

### Option 2: Direct Connection String

You can also connect directly without environment variables:

```python
import pymongo

# Direct connection to MongoDB
client = pymongo.MongoClient("mongodb://localhost:27017/")
db = client["sbom_test"]

# Access collections
pypi_collection = db["Updated_pypi_metadata"]
maven_collection = db["Updated_maven_metadata"]
go_collection = db["Updated_go_metadata"]
```

### Important Notes

- **MongoDB must be running**: Make sure you've started MongoDB in this folder first:
  ```bash
  cd /path/to/sbom_job
  docker-compose up -d
  ```

- **Same VM/Server**: This connection only works on the same VM. MongoDB is bound to `localhost:27017`, which is accessible from any folder on the same machine.

- **Database and Collections**: 
  - Database: `sbom_test` (or whatever you set in `MONGO_DB_NAME`)
  - Collections: `Updated_pypi_metadata`, `Updated_maven_metadata`, `Updated_go_metadata`

### Testing the Connection

You can test the connection from any folder:

```python
import pymongo

try:
    client = pymongo.MongoClient("mongodb://localhost:27017/", serverSelectionTimeoutMS=2000)
    client.server_info()  # Force connection
    print("✓ Successfully connected to MongoDB")
    
    db = client["sbom_test"]
    collections = db.list_collection_names()
    print(f"✓ Database 'sbom_test' found with {len(collections)} collections")
    print(f"  Collections: {collections}")
except Exception as e:
    print(f"✗ Connection failed: {e}")
    print("Make sure MongoDB is running: cd /path/to/sbom_job && docker-compose up -d")
```

### Quick Start Example

See `mongodb_connection_example.py` in this folder for a complete working example that you can copy to your other folder. It includes:
- Connection setup with environment variables
- Connection testing
- Example queries for PyPI, Maven, and Go packages

## Running the Scripts

### PyPI Package Sync

Syncs all packages from PyPI:

```bash
python script_pypi.py
```

Collection: `Updated_pypi_metadata`

### Maven Central Sync

Syncs artifacts from Maven Central:

```bash
python script_maven.py
```

Collection: `Updated_maven_metadata`

### Go Modules Sync

Syncs Go modules from the Go index:

```bash
python script_go.py
```

Collection: `Updated_go_metadata`

## How It Works

1. **SHA-based Change Detection**: Each script calculates a SHA-256 hash of the package metadata
2. **Comparison**: Compares the new SHA with existing SHA in the database
3. **Actions**:
   - **Insert**: New package (no existing SHA)
   - **Update**: SHA changed (metadata updated)
   - **Skip**: SHA unchanged (no update needed)

This approach minimizes database writes and only updates when package metadata actually changes.

## MongoDB Collections

Each script writes to its own collection:
- `Updated_pypi_metadata` - PyPI packages
- `Updated_maven_metadata` - Maven artifacts
- `Updated_go_metadata` - Go modules

All collections use a unique index on `package_name` for efficient lookups.

## Data Persistence

MongoDB data is persisted in the `./mongodb_data` directory. This directory is created automatically when you start MongoDB with Docker Compose.

**Note**: The `mongodb_data` directory is excluded from git (see `.gitignore`).

## Troubleshooting

### MongoDB Connection Issues

If scripts can't connect to MongoDB:

1. Verify MongoDB is running:
   ```bash
   docker-compose ps
   ```

2. Check MongoDB logs:
   ```bash
   docker-compose logs mongodb
   ```

3. Verify the connection string in your `.env` file matches the Docker container

### Port Already in Use

If port 27017 is already in use, you can:

1. Stop the existing MongoDB instance, or
2. Change the port in `docker-compose.yml`:
   ```yaml
   ports:
     - "27018:27017"  # Use 27018 on host
   ```
   Then update `MONGO_URI` in `.env` to `mongodb://localhost:27018/`

## Production Considerations

For production deployments:

1. Enable MongoDB authentication in `docker-compose.yml`:
   ```yaml
   environment:
     - MONGO_INITDB_ROOT_USERNAME=admin
     - MONGO_INITDB_ROOT_PASSWORD=your_secure_password
   ```

2. Update `MONGO_URI` in `.env`:
   ```env
   MONGO_URI=mongodb://admin:your_secure_password@localhost:27017/
   ```

3. Use a proper volume mount path instead of `./mongodb_data` for production data storage

4. Configure proper backup strategies for the MongoDB data volume

