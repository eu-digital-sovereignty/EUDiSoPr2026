# Reference outputs

These files are the subset of generated outputs directly supporting
`section.tex`:

- `analysis_coverage_summary.json`: crawl inclusion and sector coverage.
- `failure_reasons_summary.json`: exclusion reasons and the Lithuanian
  government HTTP 403 result.
- `any_outside_request_summary.json`: all-event outside-EU request denominator.
- `in_eu_request_summary.json`: all-event request shares by sector and
  country-sector, including the Web Layer country-score input.
- `web_content_summary.json`: machine-readable measurement summary.
- `resource_type_location_probability_by_sector.csv` and the corresponding PDF:
  the resource-type figure and its values.
- `resource_pattern_domain_evidence.json`: evidence for named web resources.
- `asn_org_any_request_domain_share*.csv`: request-destination prevalence.
- `blocking_effect_by_sector.csv`: raw visual and HTML loss values cited by the
  current section.

The set of files can be regenerated from the packaged raw databases.