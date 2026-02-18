# Cisco FMC Sample Automation Scripts

Python scripts for different operations on Cisco Firewall Management Center (FMC) using REST API.

---

## Installation

```bash
pip install -r requirements.txt
```

---

## Scripts

### 1. Network Objects (`cisco_fmc_bulk_network_objects.py`)

Create/delete network host objects.

**Create 1000 objects:**
```bash
python3 cisco_fmc_bulk_network_objects.py \
  -s 192.168.1.10 -u admin -p Password123 \
  -n 1000 --prefix NET_OBJ
```

**Delete all objects:**
```bash
python3 cisco_fmc_bulk_network_objects.py \
  -s 192.168.1.10 -u admin -p Password123 \
  --prefix NET_OBJ --clear-all
```

---

### 2. Port Objects (`cisco_fmc_bulk_port_objects.py`)

Create/delete TCP/UDP port objects.

**Create 500 mixed ports:**
```bash
python3 cisco_fmc_bulk_port_objects.py \
  -s 192.168.1.10 -u admin -p Password123 \
  -n 500 --port-type mixed
```

**Create TCP-only ports:**
```bash
python3 cisco_fmc_bulk_port_objects.py \
  -s 192.168.1.10 -u admin -p Password123 \
  -n 200 --port-type tcp --prefix TCP_PORT
```

**Delete all ports:**
```bash
python3 cisco_fmc_bulk_port_objects.py \
  -s 192.168.1.10 -u admin -p Password123 \
  --prefix PORT_OBJ --clear-all
```

**Port types:** `tcp`, `udp`, `mixed`, `ranges`

---

### 3. Access Rules (`cisco_fmc_bulk_access_rules.py`)

Create/delete access control policies and rules.

**Create policy with 1000 rules:**
```bash
python3 cisco_fmc_bulk_access_rules.py \
  -s 192.168.1.10 -u admin -p Password123 \
  --policy TEST_POLICY -n 1000
```

**Create ALLOW-only rules:**
```bash
python3 cisco_fmc_bulk_access_rules.py \
  -s 192.168.1.10 -u admin -p Password123 \
  --policy PROD_POLICY -n 500 --variety allow
```

**Delete specific rules:**
```bash
python3 cisco_fmc_bulk_access_rules.py \
  -s 192.168.1.10 -u admin -p Password123 \
  --policy TEST_POLICY --prefix RULE --clear-rules
```

**Delete entire policy:**
```bash
python3 cisco_fmc_bulk_access_rules.py \
  -s 192.168.1.10 -u admin -p Password123 \
  --policy TEST_POLICY --delete-policy
```

**Rule varieties:** `allow`, `block`, `monitor`, `mixed`

---

## Common Arguments

| Argument | Description | Default |
|----------|-------------|---------|
| `-s, --server` | FMC server IP/hostname | Required |
| `-u, --username` | FMC username | Required |
| `-p, --password` | FMC password | Required |
| `-n, --number` | Number of objects to create | - |
| `--prefix` | Prefix for object names | Varies by script |
| `--clear-all` | Delete all objects with prefix | - |
| `--max-workers` | Parallel threads for deletion | 5 |
| `--rate-limit` | Max requests per minute | 80 |

---

## Troubleshooting

**429 Rate Limit Errors:**
```bash
--max-workers 3 --rate-limit 60
```

**Bulk API Fails:**
```bash
--individual
```

## Security Warning

⚠️ Scripts disable SSL verification. In production:
- Use proper SSL certificates
- Don't hardcode credentials

### Parameters

- `-s, --server`: FMC server IP address or hostname (required)
- `-u, --username`: FMC username (required)
- `-p, --password`: FMC password (required)
- `-n, --number`: Number of network objects to create (required)
- `-d, --domain`: FMC domain name (default: Global)
- `--prefix`: Prefix for object names (default: NET_OBJ)
- `--batch-size`: Number of objects per batch (default: 1000)
- `--individual`: Use individual creation instead of bulk (fallback mode)