# Project Guardian 2.0 
Solution for Real-time PII Defense challenge.

## Run
```bash
python3 detector_full_candidate_name.py iscp_pii_dataset.csv
```

It creates `redacted_output_candidate_full_name.csv` with 3 columns.

## Redaction Examples
- Phone: 98XXXXXX10
- Aadhar: XXXX XXXX 9012
- Passport: PXXXXX67
- UPI: usXXXX@ybl
- Email: joXXXX@gmail.com
- Name: RXXXX KXXXX
- Address/city/pin: [REDACTED_PII]
- IP: 192.168.1.x
- Device ID: XXXXX1234
