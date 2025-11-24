# cloud-honeypot-tpot-oracle


T-Pot cloud honeypot deployed on Oracle Cloud with automated data analysis, threat intelligence enrichment, and visualisations.

## Features

- T-Pot multi-honeypot stack running in Oracle Cloud to capture real-world attacks.
- Python scripts for cleaning, aggregating and analysing honeypot logs.
- Threat intelligence and MITRE ATT&CK mapping for observed indicators.
- Basic machine-learning experiments and result exports for further study.
- Project report and documentation for academic submission.

## Repository structure

- `src/`
  - `analyze_honeypot.py` – main analysis script for processed honeypot logs.
  - `process_data1.py` – data cleaning and aggregation pipeline.
  - `visualizations.py` – scripts to generate charts/plots from the datasets.
  - `threat_intel.py` – enrichment using external threat-intelligence sources.
  - `mitre_mapping.py` – maps findings to MITRE ATT&CK tactics and techniques.
  - `ml_analysis.py` – machine-learning experiments on the cleaned dataset.
  - `generate_report.py` – helper to summarise results into text/figures.
  - `ml_results.json` – stored model metrics and configuration used by ML scripts.
  - `mitre_attack_mapping.json` – JSON mapping used by MITRE-related scripts.

- `data/`
  - `cleaned_honeypot_data.csv` – cleaned event dataset derived from T-Pot logs.
  - `honeypot_analysis.csv` – aggregated statistics per IP, port, protocol, etc.
  - `threat_intel_results.csv` – threat-intel enrichment results for key indicators.
  - `ml_results.json` – machine-learning output (scores, labels, predictions).
  - `mitre_attack_mapping.json` – MITRE ATT&CK mapping reference used in analysis.

- `docs/`
  - Project report and supporting documentation (final write-up, figures, etc.).

## Quick start

1. Clone the repository:

   git clone https://github.com/sri2002-lab/cloud-honeypot-tpot-oracle.git
   cd cloud-honeypot-tpot-oracle

2. Create and activate a virtual environment, then install dependencies:
   pip install -r requirements.txt

3. Run the main analysis pipeline:
   python src/process_data1.py
   python src/analyze_honeypot.py

4.  Generate visualisations or additional reports:
   python src/visualizations.py
   python src/generate_report.py


## Academic context

This repository is part of a network security project using T-Pot on Oracle Cloud to capture real-world attacks, clean and analyse the data with Python, enrich it with threat intelligence and MITRE ATT&CK, and document the findings for assessment.
   

