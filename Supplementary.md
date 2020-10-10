
## Product information extraction
CPE is a standardized method of describing and identifying classes of applications, operating systems, and hardware devices present among an enterprise’s computing assets. CPE identifiers provided by NVD are used to assign a particular vulnerability to a certain product out of the three main groups: (i) operating systems, (ii) application software and (iii) hardware components (e.g. routers, graphical cards, embedded devices, etc.). Below shows the CPE identifier for the software product Microsoft Internet Explorer 8.
```
{
  "part" : "a",
  "vendor" : "microsoft",
  "product" : "internet explorer",
  "version" : "8",
  "update" : "NA",
  "edition" : "ANY",
  "language" : "ANY",
  "sw_edition" : "ANY",
  "target_sw" : "ANY",
  "target_hw" : "ANY",
  "other" : "ANY"
}
```
To define the affected products precisely, logical operators can be used to combine multiple CPE identifiers. `Or` operator is used when multiple products are affected by the vulnerability. `And` operator is used when the vulnerability is only applicable for affected products under a specific context. For example, some vulnerabilities only influence applications on specific operating systems, and the corresponding CPE identifier consist of identifiers for applications and operating systems. In our analysis, we drop the context part from the CPE identifiers, as these products are not affected by the vulnerabilities exactly. After that, we extract the product names (``product'' field in each CPE identifier) and product types (``part'' field in each CPE identifier) from the CPE identifiers. 

However, there are some inconsistencies in CPE identifiers, and we manually fix these issues by examining the related resources of each vulnerability.
- Some context are expressed with `And` operator instead of `Or` operator.
- The product name is changed for different reasons, such as transition between products and acquisition between vendors.


## Keyword-based search
Following are the code we used to perform keyword-based search. Basically, we extract the description for each vulnerability, remove all confusing words, and search specific keywords.
```python
def get_cves_by_keywords():
    # sensitive, sensitivity, private, privacy, credential, credentials, password, passwords,
    # certificate, certificates, authorize, authorization, expose, exposure, discosure, mask, world-readable, session
    keywords = ["sensiti", "priva", "secret", "credential", "password", "certifi", "authoriz", "expos",
                "disclos", "mask", "readable", "session"]
    DATA_DIR = "F:/Data/NVD"
    data = []
    count = 0
    for name in os.listdir(DATA_DIR):
        if name.endswith(".json"):
            print(name)
            with open(os.path.join(DATA_DIR, name), encoding="UTF-8", errors="ignore") as json_file:
                cves = json.load(json_file)
                cve_items = cves["CVE_Items"]
                for item in cve_items:
                    description = item["cve"]["description"]["description_data"]
                    for value in description:
                        description_text = value["value"].lower()
                        description_text = description_text.\
                            replace("logi", "").replace("blog", "").replace("technolog", "").\
                            replace("dialog", "").replace("catalog", "").replace("terminology", "").\
                            replace("analog", "").replace("micrologix", "").replace("synology", "").replace("simplog", "").\
                            replace("login", "").replace("logout", "").replace("logon", "").\
                            replace("log-in", "").replace("log-out", "").replace("log-on", ""). \
                            replace("log in", "").replace("log into", "").replace("log out", "").replace("log on", ""). \
                            replace("logging in", "").replace("logging out", "").replace("logging on", "").\
                            replace("logged in", "").replace("logged out", "").replace("logged on", "")
                        if "log" in description_text:
                            matched = False
                            for word in keywords:
                                if word in description_text:
                                    matched = True
                                    break
                            if matched:
                                data.append(item)
                                count += 1

    with open("search_result.json", "w") as output:
        json.dump({"Count": count, "CVES": data}, output, indent=2)
```

## Time-based filtration
As we explain the Section 2, we use the CVSS score to measure the exploitability and impacts of vulnerabilities. In fact, there are many versions for CVSS, and we use the lastest CVSS v3.x in our study. However, CVSS v3.x was released in June 2015. Many vulnerabilities are measured with previous version of CVSS, and most of these vulnerabilities are disclosed before 2015. Therefore, we drop all these vulnerabilities without CVSS v3.x score.