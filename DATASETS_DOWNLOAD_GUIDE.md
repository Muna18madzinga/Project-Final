# Dataset Download Guide for Adaptive Security System

This guide provides download links and instructions for all datasets used to train the ML models in this adaptive security system.

---

## 📊 Primary Datasets

### 1. UNSW-NB15 Dataset

**Description:** Network intrusion detection dataset from Australian Centre for Cyber Security (ACCS)

**Features:** 49 features capturing network flow statistics
**Samples:** ~2.5 million records
**Attack Types:** 9 categories
- Normal (87%)
- Generic (2%)
- Exploits (3%)
- Fuzzers (2%)
- DoS (2%)
- Reconnaissance (1%)
- Analysis (1%)
- Backdoor (1%)
- Shellcode (0.5%)
- Worms (0.5%)

**Download Links:**

**Option 1: Official Source (Recommended)**
- **Website:** https://research.unsw.edu.au/projects/unsw-nb15-dataset
- **Direct Link:** https://cloudstor.aarnet.edu.au/plus/index.php/s/2DhnLGDdEECo4ys
- **Files Needed:**
  - `UNSW-NB15_1.csv` (700 MB)
  - `UNSW-NB15_2.csv` (648 MB)
  - `UNSW-NB15_3.csv` (630 MB)
  - `UNSW-NB15_4.csv` (582 MB)
  - `UNSW_NB15_training-set.csv` (157 MB)
  - `UNSW_NB15_testing-set.csv` (95 MB)

**Option 2: Kaggle**
- **Link:** https://www.kaggle.com/datasets/mrwellsdavid/unsw-nb15
- **Format:** CSV files
- **Size:** ~2.5 GB total

**Option 3: UCI Machine Learning Repository**
- **Link:** https://www.unsw.adfa.edu.au/unsw-canberra-cyber/cybersecurity/ADFA-NB15-Datasets/

**Feature Documentation:**
- Download: `NUSW-NB15_features.csv` (feature descriptions)
- Download: `UNSW-NB15_LIST_EVENTS.csv` (attack event list)

**Installation Command:**
```bash
# Create data directory
mkdir -p data/unsw_nb15

# Download using wget (Linux/Mac)
cd data/unsw_nb15
wget https://cloudstor.aarnet.edu.au/plus/index.php/s/2DhnLGDdEECo4ys?path=%2FUNSW-NB15%20-%20CSV%20Files -O unsw_nb15.zip
unzip unsw_nb15.zip

# Or download manually and place in data/unsw_nb15/
```

**Usage in Code:**
```python
from app.data_preprocessing import get_dataset_processor

processor = get_dataset_processor()
df = processor.load_unsw_nb15('data/unsw_nb15/UNSW_NB15_training-set.csv')
```

---

### 2. CIC-IDS2018 Dataset

**Description:** Comprehensive intrusion detection dataset from Canadian Institute for Cybersecurity

**Features:** 80 features including flow statistics and packet inspection
**Samples:** ~16 million records
**Attack Types:** 16 categories
- Benign (81%)
- Brute Force - FTP (0.5%)
- Brute Force - SSH (0.5%)
- DoS attacks - GoldenEye (1%)
- DoS attacks - Slowloris (1%)
- DoS attacks - Hulk (2%)
- DoS attacks - SlowHTTPTest (1%)
- DDoS attacks - LOIC-HTTP (2%)
- DDoS attacks - HOIC (1.5%)
- Heartbleed (0.3%)
- Web Attack - Brute Force (0.8%)
- Web Attack - XSS (0.9%)
- Web Attack - SQL Injection (1.2%)
- Infiltration (0.2%)
- Botnet (1%)
- Port Scan (3%)

**Download Links:**

**Option 1: Official Source (Recommended)**
- **Website:** https://www.unb.ca/cic/datasets/ids-2018.html
- **AWS Link:** https://www.unb.ca/cic/datasets/ids-2018.html
- **Files Needed:**
  - Download all CSV files (10 days of captures)
  - Total size: ~7 GB compressed, ~60 GB uncompressed

**Option 2: Kaggle**
- **Link:** https://www.kaggle.com/datasets/solarmainframe/ids-intrusion-csv
- **Format:** Pre-processed CSV
- **Size:** ~6 GB

**Option 3: Google Drive (Community)**
- **Link:** https://drive.google.com/drive/folders/1ArWkXjIsfvIGJA2B5sS8dxn9xpKUCp2e
- **Note:** Verify checksums after download

**Daily Capture Files:**
```
Thuesday-20-02-2018_TrafficForML_CICFlowMeter.csv
Wednesday-21-02-2018_TrafficForML_CICFlowMeter.csv
Thursday-22-02-2018_TrafficForML_CICFlowMeter.csv
Friday-23-02-2018_TrafficForML_CICFlowMeter.csv
Thuesday-27-02-2018_TrafficForML_CICFlowMeter.csv
Wednesday-28-02-2018_TrafficForML_CICFlowMeter.csv
Thursday-01-03-2018_TrafficForML_CICFlowMeter.csv
Friday-02-03-2018_TrafficForML_CICFlowMeter.csv
```

**Installation Command:**
```bash
# Create data directory
mkdir -p data/cic_ids2018

# Download using wget (example for one file)
cd data/cic_ids2018
wget https://[direct-link]/Thursday-22-02-2018_TrafficForML_CICFlowMeter.csv

# Or use Kaggle CLI
pip install kaggle
kaggle datasets download -d solarmainframe/ids-intrusion-csv
unzip ids-intrusion-csv.zip -d data/cic_ids2018/
```

**Usage in Code:**
```python
from app.data_preprocessing import get_dataset_processor

processor = get_dataset_processor()
df = processor.load_cic_ids2018('data/cic_ids2018/Thursday-22-02-2018_TrafficForML_CICFlowMeter.csv')
```

---

## 📦 Alternative/Supplementary Datasets

### 3. NSL-KDD Dataset

**Description:** Improved version of KDD Cup 99 dataset (legacy but widely used)

**Features:** 41 features
**Samples:** ~150,000 records
**Attack Types:** 4 main categories (DoS, Probe, R2L, U2R)

**Download Links:**
- **Official:** https://www.unb.ca/cic/datasets/nsl.html
- **Kaggle:** https://www.kaggle.com/datasets/hassan06/nslkdd
- **Direct:** https://github.com/defcom17/NSL_KDD

**Files:**
- `KDDTrain+.txt` - Training set (125,973 records)
- `KDDTest+.txt` - Test set (22,544 records)
- `KDDTrain+_20Percent.txt` - 20% subset (25,192 records)

```bash
mkdir -p data/nsl_kdd
cd data/nsl_kdd
wget https://github.com/defcom17/NSL_KDD/raw/master/KDDTrain%2B.txt
wget https://github.com/defcom17/NSL_KDD/raw/master/KDDTest%2B.txt
```

---

### 4. CICIDS2017 Dataset

**Description:** Predecessor to CIC-IDS2018, still widely used

**Features:** 78 features
**Samples:** ~2.8 million records
**Attack Types:** 7 categories

**Download Links:**
- **Official:** https://www.unb.ca/cic/datasets/ids-2017.html
- **Kaggle:** https://www.kaggle.com/datasets/cicdataset/cicids2017

```bash
mkdir -p data/cicids2017
cd data/cicids2017
kaggle datasets download -d cicdataset/cicids2017
unzip cicids2017.zip
```

---

### 5. CTU-13 Dataset (Botnet Traffic)

**Description:** Botnet traffic captures from CTU University

**Features:** Netflow records
**Samples:** 13 scenarios of different botnets
**Size:** ~85 GB

**Download Link:**
- **Official:** https://www.stratosphereips.org/datasets-ctu13
- **Download:** https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-42/

```bash
mkdir -p data/ctu13
cd data/ctu13
wget https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-42/detailed-bidirectional-flow-labels/capture20110810.binetflow
```

---

### 6. DARPA Intrusion Detection Evaluation

**Description:** Classic intrusion detection dataset

**Download Link:**
- **Official:** https://www.ll.mit.edu/r-d/datasets/1998-darpa-intrusion-detection-evaluation-dataset
- **Mirror:** https://www.ll.mit.edu/r-d/datasets/1999-darpa-intrusion-detection-evaluation-dataset

---

## 🔧 Dataset Preprocessing Scripts

### Quick Setup Script

Create `scripts/download_datasets.sh`:

```bash
#!/bin/bash

echo "Downloading datasets for Adaptive Security System..."

# Create directories
mkdir -p data/{unsw_nb15,cic_ids2018,nsl_kdd,cicids2017}

# Function to download with progress
download_file() {
    url=$1
    output=$2
    echo "Downloading $output..."
    wget --progress=bar:force:noscroll "$url" -O "$output"
}

# Download UNSW-NB15 (Kaggle - requires API key)
echo "Downloading UNSW-NB15..."
cd data/unsw_nb15
kaggle datasets download -d mrwellsdavid/unsw-nb15
unzip unsw-nb15.zip
cd ../..

# Download NSL-KDD
echo "Downloading NSL-KDD..."
cd data/nsl_kdd
download_file "https://github.com/defcom17/NSL_KDD/raw/master/KDDTrain%2B.txt" "KDDTrain+.txt"
download_file "https://github.com/defcom17/NSL_KDD/raw/master/KDDTest%2B.txt" "KDDTest+.txt"
cd ../..

# Download CIC-IDS2018 (Kaggle)
echo "Downloading CIC-IDS2018..."
cd data/cic_ids2018
kaggle datasets download -d solarmainframe/ids-intrusion-csv
unzip ids-intrusion-csv.zip
cd ../..

echo "Dataset download complete!"
echo "Total size: ~15 GB"
```

Make executable and run:
```bash
chmod +x scripts/download_datasets.sh
./scripts/download_datasets.sh
```

---

### Python Download Script

Create `scripts/download_datasets.py`:

```python
import os
import requests
import zipfile
from tqdm import tqdm

def download_file(url, filename):
    """Download file with progress bar."""
    response = requests.get(url, stream=True)
    total_size = int(response.headers.get('content-length', 0))

    with open(filename, 'wb') as file, tqdm(
        desc=filename,
        total=total_size,
        unit='B',
        unit_scale=True,
        unit_divisor=1024,
    ) as bar:
        for data in response.iter_content(chunk_size=1024):
            size = file.write(data)
            bar.update(size)

def setup_datasets():
    """Download all required datasets."""

    # Create directories
    os.makedirs('data/unsw_nb15', exist_ok=True)
    os.makedirs('data/cic_ids2018', exist_ok=True)
    os.makedirs('data/nsl_kdd', exist_ok=True)

    print("📦 Downloading NSL-KDD...")
    download_file(
        'https://github.com/defcom17/NSL_KDD/raw/master/KDDTrain%2B.txt',
        'data/nsl_kdd/KDDTrain+.txt'
    )

    print("📦 Downloading NSL-KDD Test...")
    download_file(
        'https://github.com/defcom17/NSL_KDD/raw/master/KDDTest%2B.txt',
        'data/nsl_kdd/KDDTest+.txt'
    )

    print("✅ Dataset download complete!")
    print("\nFor UNSW-NB15 and CIC-IDS2018, please:")
    print("1. Visit https://www.kaggle.com/datasets/mrwellsdavid/unsw-nb15")
    print("2. Visit https://www.kaggle.com/datasets/solarmainframe/ids-intrusion-csv")
    print("3. Download and place in data/ directory")

if __name__ == '__main__':
    setup_datasets()
```

Run:
```bash
python scripts/download_datasets.py
```

---

## 📂 Expected Directory Structure

After downloading all datasets:

```
project-main/
├── data/
│   ├── unsw_nb15/
│   │   ├── UNSW-NB15_1.csv
│   │   ├── UNSW-NB15_2.csv
│   │   ├── UNSW-NB15_3.csv
│   │   ├── UNSW-NB15_4.csv
│   │   ├── UNSW_NB15_training-set.csv
│   │   └── UNSW_NB15_testing-set.csv
│   ├── cic_ids2018/
│   │   ├── Thuesday-20-02-2018_TrafficForML_CICFlowMeter.csv
│   │   ├── Wednesday-21-02-2018_TrafficForML_CICFlowMeter.csv
│   │   ├── Thursday-22-02-2018_TrafficForML_CICFlowMeter.csv
│   │   ├── Friday-23-02-2018_TrafficForML_CICFlowMeter.csv
│   │   └── ... (more daily files)
│   ├── nsl_kdd/
│   │   ├── KDDTrain+.txt
│   │   ├── KDDTest+.txt
│   │   └── KDDTrain+_20Percent.txt
│   └── cicids2017/
│       ├── Monday-WorkingHours.pcap_ISCX.csv
│       ├── Tuesday-WorkingHours.pcap_ISCX.csv
│       └── ... (more daily files)
├── app/
└── scripts/
```

---

## 🚀 Training with Downloaded Datasets

### Example 1: Train with UNSW-NB15

```python
from app.data_preprocessing import get_dataset_processor
from app.pytorch_detector import get_pytorch_runtime

# Load dataset
processor = get_dataset_processor()
df = processor.load_unsw_nb15('data/unsw_nb15/UNSW_NB15_training-set.csv')

# Preprocess
processed = processor.process_dataset(
    df,
    dataset_name='unsw_nb15',
    target_column='attack_cat',
    test_size=0.2,
    validation_size=0.1
)

# Train PyTorch model
runtime = get_pytorch_runtime()
runtime.train_model(
    model_name='cnn_detector',
    train_data=df,
    target_column='attack_cat',
    epochs=50,
    batch_size=64
)
```

### Example 2: Train with CIC-IDS2018

```python
from app.data_preprocessing import get_dataset_processor

processor = get_dataset_processor()

# Load multiple days
df_list = []
for day_file in [
    'Thursday-22-02-2018_TrafficForML_CICFlowMeter.csv',
    'Friday-23-02-2018_TrafficForML_CICFlowMeter.csv'
]:
    df = processor.load_cic_ids2018(f'data/cic_ids2018/{day_file}')
    df_list.append(df)

# Combine
import pandas as pd
df_combined = pd.concat(df_list, ignore_index=True)

# Preprocess and train
processed = processor.process_dataset(
    df_combined,
    dataset_name='cic_ids2018',
    target_column='Label',
    test_size=0.2
)
```

---

## 📊 Dataset Comparison

| Dataset | Features | Samples | Size | Attack Types | Year |
|---------|----------|---------|------|--------------|------|
| **UNSW-NB15** | 49 | 2.5M | 2.5 GB | 9 | 2015 |
| **CIC-IDS2018** | 80 | 16M | 60 GB | 16 | 2018 |
| **NSL-KDD** | 41 | 150K | 50 MB | 4 | 2009 |
| **CICIDS2017** | 78 | 2.8M | 5 GB | 7 | 2017 |
| **CTU-13** | Netflow | Varies | 85 GB | Botnets | 2011 |

**Recommendation:**
- **Start with:** UNSW-NB15 (smaller, faster to train)
- **Production use:** CIC-IDS2018 (most comprehensive)
- **Legacy comparison:** NSL-KDD (benchmark against other research)

---

## ⚠️ Important Notes

### Storage Requirements
- **Minimum:** 10 GB free space (UNSW-NB15 + NSL-KDD)
- **Recommended:** 100 GB free space (all datasets)
- **Optimal:** 200 GB+ (for processed datasets + models)

### Memory Requirements
- **Training UNSW-NB15:** 8 GB RAM minimum
- **Training CIC-IDS2018:** 16 GB RAM minimum (32 GB recommended)
- **Preprocessing:** 2× dataset size in RAM

### Download Time Estimates
- **UNSW-NB15:** ~30 minutes (100 Mbps connection)
- **CIC-IDS2018:** ~2-3 hours (100 Mbps connection)
- **NSL-KDD:** ~2 minutes (100 Mbps connection)

---

## 🔐 Data Integrity Verification

### Verify Downloads with Checksums

For UNSW-NB15:
```bash
# MD5 checksums (verify after download)
md5sum data/unsw_nb15/UNSW_NB15_training-set.csv
# Expected: [check official documentation]
```

For CIC-IDS2018:
```bash
sha256sum data/cic_ids2018/*.csv
# Compare with official checksums
```

---

## 📚 Dataset Citations

If you use these datasets in research, please cite:

**UNSW-NB15:**
```
Moustafa, Nour, and Jill Slay. "UNSW-NB15: a comprehensive data set for
network intrusion detection systems (UNSW-NB15 network data set)."
Military Communications and Information Systems Conference (MilCIS), 2015.
```

**CIC-IDS2018:**
```
Sharafaldin, Iman, Arash Habibi Lashkari, and Ali A. Ghorbani.
"Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic
Characterization." ICISSP. 2018.
```

**NSL-KDD:**
```
Tavallaee, Mahbod, et al. "A detailed analysis of the KDD CUP 99 data set."
IEEE Symposium on Computational Intelligence for Security and Defense Applications, 2009.
```

---

## 🆘 Troubleshooting

### Problem: Kaggle API not working

**Solution:**
1. Create Kaggle account
2. Go to https://www.kaggle.com/settings/account
3. Click "Create New API Token"
4. Save `kaggle.json` to `~/.kaggle/` (Linux/Mac) or `C:\Users\<username>\.kaggle\` (Windows)

```bash
pip install kaggle
mkdir -p ~/.kaggle
cp ~/Downloads/kaggle.json ~/.kaggle/
chmod 600 ~/.kaggle/kaggle.json
```

### Problem: Out of disk space

**Solution:** Download subsets or use streaming
```python
# Load in chunks
chunk_size = 100000
for chunk in pd.read_csv('large_dataset.csv', chunksize=chunk_size):
    process(chunk)
```

### Problem: Dataset format issues

**Solution:** Check encoding and delimiters
```python
# Try different encodings
df = pd.read_csv('dataset.csv', encoding='latin1')
df = pd.read_csv('dataset.csv', encoding='utf-8', on_bad_lines='skip')
```

---

## 📧 Support

For dataset-related issues:
- **UNSW-NB15:** Contact ACCS at unsw.adfa.edu.au
- **CIC Datasets:** Contact UNB CIC at cic@unb.ca
- **System Issues:** Create GitHub issue in this repository

---

## ✅ Quick Start Checklist

- [ ] Create `data/` directory structure
- [ ] Install Kaggle CLI (`pip install kaggle`)
- [ ] Download UNSW-NB15 dataset
- [ ] Download CIC-IDS2018 dataset (optional but recommended)
- [ ] Download NSL-KDD dataset (for benchmarking)
- [ ] Verify checksums
- [ ] Test loading with provided code examples
- [ ] Run initial preprocessing
- [ ] Train first model

**Total Time:** 3-4 hours (including downloads)

---

**Last Updated:** January 2025
