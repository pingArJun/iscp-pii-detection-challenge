#!/usr/bin/env python3

import csv
import json
import sys

def parse_json(s):
    try:
        return json.loads(s)
    except:
        try:
            s2 = s.replace("'", '"')
            return json.loads(s2)
        except:
            return {}

def is_phone(num):
    num = str(num).replace(" ", "")
    return num.isdigit() and len(num) == 10

def mask_phone(num):
    num = str(num).replace(" ", "")
    return num[:2] + "X" * 6 + num[-2:]

def is_aadhar(num):
    digits = "".join([c for c in str(num) if c.isdigit()])
    return len(digits) == 12

def mask_aadhar(num):
    digits = "".join([c for c in str(num) if c.isdigit()])
    return "XXXX XXXX " + digits[-4:]

def is_passport(p):
    s = str(p).strip().upper()
    return len(s) == 8 and s[0].isalpha() and s[1:].isdigit()

def mask_passport(p):
    s = str(p).strip().upper()
    return s[0] + "X" * 5 + s[-2:]

def is_upi(u):
    return isinstance(u, str) and "@" in u

def mask_upi(u):
    parts = u.split("@")
    if len(parts[0]) <= 2:
        left = "XX"
    else:
        left = parts[0][:2] + "X" * (len(parts[0]) - 2)
    return left + "@" + parts[1]

def is_email(e):
    return isinstance(e, str) and "@" in e and "." in e

def mask_email(e):
    parts = e.split("@")
    if len(parts[0]) <= 2:
        left = "XX"
    else:
        left = parts[0][:2] + "X" * (len(parts[0]) - 2)
    return left + "@" + parts[1]

def is_full_name(n):
    if not isinstance(n, str):
        return False
    parts = [x for x in n.strip().split() if x]
    return len(parts) >= 2

def mask_name(n):
    parts = n.strip().split()
    out = []
    for p in parts:
        if len(p) > 1:
            out.append(p[0] + "X" * (len(p) - 1))
        else:
            out.append(p)
    return " ".join(out)

def mask_device_id(d):
    s = str(d).strip()
    if len(s) <= 4:
        return "XXXX"
    return "X" * (len(s) - 4) + s[-4:]

def mask_ip(ip):
    s = str(ip).strip()
    parts = s.split(".")
    if len(parts) == 4:
        parts[-1] = "x"
        return ".".join(parts)
    return "[REDACTED_PII]"

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 detector_full_candidate_name.py iscp_pii_dataset.csv")
        sys.exit(1)

    infile = sys.argv[1]
    outfile = "redacted_output_candidate_full_name.csv"

    out_rows = []

    with open(infile, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            rid = row.get("record_id")
            raw_json = row.get("Data_json") or row.get("data_json") or ""
            data = parse_json(raw_json)
            if not isinstance(data, dict):
                data = {}

            is_pii = False

            if "phone" in data and is_phone(data["phone"]):
                is_pii = True
            if "contact" in data and is_phone(data["contact"]):
                is_pii = True
            if "aadhar" in data and is_aadhar(data["aadhar"]):
                is_pii = True
            if "passport" in data and is_passport(data["passport"]):
                is_pii = True
            if "upi_id" in data and is_upi(data["upi_id"]):
                is_pii = True

            categories = set()
            if "name" in data and is_full_name(data["name"]):
                categories.add("name")
            if "first_name" in data and "last_name" in data and data["first_name"] and data["last_name"]:
                categories.add("name")
            if "email" in data and is_email(data["email"]):
                categories.add("email")
            if "pin_code" in data and (data.get("address") or data.get("city")):
                if str(data["pin_code"]).strip() != "":
                    categories.add("address")
            if ("name" in categories or "email" in categories):
                if data.get("device_id") or data.get("ip_address"):
                    categories.add("device_or_ip")

            if len(categories) >= 2:
                is_pii = True

            if is_pii:
                if "phone" in data and is_phone(data["phone"]):
                    data["phone"] = mask_phone(data["phone"])
                if "contact" in data and is_phone(data["contact"]):
                    data["contact"] = mask_phone(data["contact"])
                if "aadhar" in data and is_aadhar(data["aadhar"]):
                    data["aadhar"] = mask_aadhar(data["aadhar"])
                if "passport" in data and is_passport(data["passport"]):
                    data["passport"] = mask_passport(data["passport"])
                if "upi_id" in data and is_upi(data["upi_id"]):
                    data["upi_id"] = mask_upi(data["upi_id"])
                if "name" in data and is_full_name(data["name"]):
                    data["name"] = mask_name(data["name"])
                if "first_name" in data and data["first_name"]:
                    data["first_name"] = mask_name(data["first_name"])
                if "last_name" in data and data["last_name"]:
                    data["last_name"] = mask_name(data["last_name"])
                if "email" in data and is_email(data["email"]):
                    data["email"] = mask_email(data["email"])
                if "address" in data and data["address"]:
                    data["address"] = "[REDACTED_PII]"
                if "city" in data and data["city"]:
                    data["city"] = "[REDACTED_PII]"
                if "pin_code" in data:
                    data["pin_code"] = "[REDACTED_PII]"
                if "ip_address" in data and data["ip_address"]:
                    data["ip_address"] = mask_ip(data["ip_address"])
                if "device_id" in data and data["device_id"]:
                    data["device_id"] = mask_device_id(data["device_id"])

            out_rows.append({
                "record_id": rid,
                "redacted_data_json": json.dumps(data, ensure_ascii=False),
                "is_pii": str(is_pii)
            })

    with open(outfile, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["record_id", "redacted_data_json", "is_pii"])
        writer.writeheader()
        for row in out_rows:
            writer.writerow(row)

if __name__ == "__main__":
    main()
