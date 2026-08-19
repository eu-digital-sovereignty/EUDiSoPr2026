## EU Digital Sovereignty in Practice: A Technical Assessment of Digital Infrastructure Dependencies

### Data and scripts for reproduction:

#### domain lists (study_domains: GOV + EU)

```
domains/
banks.json		
newspapers.json		
study_domains.json 
universities.json
```

#### patterns and definitions 

```
lookup_tables/ 
ca_database.csv
cloud_providers.csv
mx_patterns.csv
provider_overrides.csv
txt_patterns.csv
```

#### data and post_processed results

```
raw_data/	
results/
```

#### scanning scripts & visualisation code

```
scanner/
visualization/
```

#### Web Content reproducibility artifact

The code, compact crawl databases, reference outputs, and the manuscript's Web
Content section are provided under [`web_content/`](web_content/).
From that directory, run:

```bash
python3 -m venv .venv
.venv/bin/pip install -r analysis/requirements.txt
.venv/bin/python analysis/reproduce.py
```

Large screenshot and HAR archives are not included in this repository and are
available from the authors on request.
