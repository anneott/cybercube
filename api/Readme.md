
# Part 3 API

API is built using Python framework FastAPI which is one of the quickest Python web frameworks available.
It automatically generates interactive API documentation which makes the API development easy directly from the browser.
FastAPI uses Pydantic for data validation and parsing which ensures that data passed through API is validated and types.


# Settin Up the API
1. navigate to folder api (e.g. `cd api`)
2. make sure conda environment is used (`conda activate cybercube`)
3. run api file `python api.py`
4. open in browser `localhost:8000/docs`
5. execute any of the displayed API endpoints

API contains 6 GET endpoints. 

## GET `/query_cve_id_from_api`
Input parameter `cve_id` is required. 
Outputs response from [NVD API](https://services.nvd.nist.gov/rest/json/cves/2.0) for the given CVE ID.

### Example request
```
curl -X 'GET' \
  'http://127.0.0.1:8000/query_cve_id_from_api?cve_id=CVE-2019-1010218' \
  -H 'accept: application/json'
```

### Example response
```
{
  "resultsPerPage": 1,
  "startIndex": 0,
  "totalResults": 1,
  "format": "NVD_CVE",
  "version": "2.0",
  "timestamp": "2024-08-11T19:48:02.723",
  "vulnerabilities": [
    {
      "cve": {
        "id": "CVE-2019-1010218",
        "sourceIdentifier": "josh@bress.net",
        "published": "2019-07-22T18:15:10.917",
        "lastModified": "2020-09-30T13:40:18.163",
        "vulnStatus": "Analyzed",
        "cveTags": [],
        "descriptions": [
          {
            "lang": "en",
            "value": "Cherokee Webserver Latest Cherokee Web server Upto Version 1.2.103 (Current stable) is affected by: Buffer Overflow - CWE-120. The impact is: Crash. The component is: Main cherokee command. The attack vector is: Overwrite argv[0] to an insane length with execl. The fixed version is: There's no fix yet."
          },
          {
            "lang": "es",
            "value": "El servidor web de Cherokee más reciente de Cherokee Webserver Hasta Versión 1.2.103 (estable actual) está afectado por: Desbordamiento de Búfer - CWE-120. El impacto es: Bloqueo. El componente es: Comando cherokee principal. El vector de ataque es: Sobrescribir argv[0] en una longitud no sana con execl. La versión corregida es: no hay ninguna solución aún."
          }
        ],
        "metrics": {
          "cvssMetricV31": [
            {
              "source": "nvd@nist.gov",
              "type": "Primary",
              "cvssData": {
                "version": "3.1",
                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
                "attackVector": "NETWORK",
                "attackComplexity": "LOW",
                "privilegesRequired": "NONE",
                "userInteraction": "NONE",
                "scope": "UNCHANGED",
                "confidentialityImpact": "NONE",
                "integrityImpact": "NONE",
                "availabilityImpact": "HIGH",
                "baseScore": 7.5,
                "baseSeverity": "HIGH"
              },
              "exploitabilityScore": 3.9,
              "impactScore": 3.6
            }
          ],
          "cvssMetricV2": [
            {
              "source": "nvd@nist.gov",
              "type": "Primary",
              "cvssData": {
                "version": "2.0",
                "vectorString": "AV:N/AC:L/Au:N/C:N/I:N/A:P",
                "accessVector": "NETWORK",
                "accessComplexity": "LOW",
                "authentication": "NONE",
                "confidentialityImpact": "NONE",
                "integrityImpact": "NONE",
                "availabilityImpact": "PARTIAL",
                "baseScore": 5
              },
              "baseSeverity": "MEDIUM",
              "exploitabilityScore": 10,
              "impactScore": 2.9,
              "acInsufInfo": false,
              "obtainAllPrivilege": false,
              "obtainUserPrivilege": false,
              "obtainOtherPrivilege": false,
              "userInteractionRequired": false
            }
          ]
        },
        "weaknesses": [
          {
            "source": "nvd@nist.gov",
            "type": "Primary",
            "description": [
              {
                "lang": "en",
                "value": "CWE-787"
              }
            ]
          },
          {
            "source": "josh@bress.net",
            "type": "Secondary",
            "description": [
              {
                "lang": "en",
                "value": "CWE-120"
              }
            ]
          }
        ],
        "configurations": [
          {
            "nodes": [
              {
                "operator": "OR",
                "negate": false,
                "cpeMatch": [
                  {
                    "vulnerable": true,
                    "criteria": "cpe:2.3:a:cherokee-project:cherokee_web_server:*:*:*:*:*:*:*:*",
                    "versionEndIncluding": "1.2.103",
                    "matchCriteriaId": "DCE1E311-F9E5-4752-9F51-D5DA78B7BBFA"
                  }
                ]
              }
            ]
          }
        ],
        "references": [
          {
            "url": "https://i.imgur.com/PWCCyir.png",
            "source": "josh@bress.net",
            "tags": [
              "Exploit",
              "Third Party Advisory"
            ]
          }
        ]
      }
    }
  ]
}
```

## GET `/query_cve_id_from_database`
Input parameter `cve_id` is required. 
Queries from database table `cve` given `cve_id_text`. 
The SQL query is currently returning only very basic information, but in the future
multiple tables could be combined and more information could be returned.

### Example request 
```
curl -X 'GET' \
  'http://127.0.0.1:8000/query_cve_id_from_database?cve_id=CVE-2019-1010218' \
  -H 'accept: application/json'
```

### Example response
```
{
  "cve_list": [
    {
      "id": 122630,
      "cve_id_text": "CVE-2019-1010218",
      "metadata_id": 64,
      "source_identifier": "josh@bress.net",
      "published": "2019-07-22T18:15:10.917000",
      "last_modified": "2020-09-30T13:40:18.163000",
      "vuln_status": "Analyzed"
    }
  ]
}
```

## GET `/query_severity_distribution`
Input parameter `topn` defines how many most common severities should be returned. 
From database both v2 and v3 metric severities are queried.
If there is v3 then v2 is not used, if no v3 is present then v2 is used.
Returns top severities and their occurrence counts combined for v3 and v2.

### Example request 
```
curl -X 'GET' \
  'http://127.0.0.1:8000/query_serverity_distribution?topn=10' \
  -H 'accept: application/json'
```

### Example response
```
{
  "severity_list": [
    {
      "base_severity": "MEDIUM",
      "severity_count": 102702
    },
    {
      "base_severity": "HIGH",
      "severity_count": 87241
    },
    {
      "base_severity": null,
      "severity_count": 50165
    },
    {
      "base_severity": "CRITICAL",
      "severity_count": 20119
    },
    {
      "base_severity": "LOW",
      "severity_count": 10130
    },
    {
      "base_severity": "NONE",
      "severity_count": 19
    }
  ]
}
```


## GET `/query_worst_vendors`
Input parameter `topn` defines how many worst vendors should be returned.
Queries from database vendors with the most vulnerabilities.
Returns vendor name and their vulnerability occurrence count.

### Example request
```
curl -X 'GET' \
  'http://127.0.0.1:8000/query_worst_vendors?topn=10' \
  -H 'accept: application/json'
```

### Example response
```
{
  "vendor_vulnerabilities": [
    {
      "vendor": "qualcomm",
      "vulnerability_count": 138007
    },
    {
      "vendor": "intel",
      "vulnerability_count": 32149
    },
    {
      "vendor": "dell",
      "vulnerability_count": 24639
    },
    {
      "vendor": "hp",
      "vulnerability_count": 18211
    },
    {
      "vendor": "cisco",
      "vulnerability_count": 16077
    },
    {
      "vendor": "microsoft",
      "vulnerability_count": 13520
    },
    {
      "vendor": "google",
      "vulnerability_count": 10760
    },
    {
      "vendor": "amd",
      "vulnerability_count": 10753
    },
    {
      "vendor": "oracle",
      "vulnerability_count": 10154
    },
    {
      "vendor": "netgear",
      "vulnerability_count": 10003
    }
  ]
}
```


## GET `/query_worst_products`
Input parameter `topn` defines how many worst products should be returned.
Queries from database products with the most vulnerabilities.
Returns product name and their vulnerability occurrence count.

### Example request
```
curl -X 'GET' \
  'http://127.0.0.1:8000/query_worst_products?topn=10' \
  -H 'accept: application/json'
```

### Example response
```
{
  "product_vulnerabilities": [
    {
      "product": "debian_linux",
      "vulnerability_count": 8486
    },
    {
      "product": "android",
      "vulnerability_count": 6848
    },
    {
      "product": "fedora",
      "vulnerability_count": 4988
    },
    {
      "product": "ubuntu_linux",
      "vulnerability_count": 3879
    },
    {
      "product": "linux_kernel",
      "vulnerability_count": 3474
    },
    {
      "product": "chrome",
      "vulnerability_count": 3352
    },
    {
      "product": "windows_server_2016",
      "vulnerability_count": 3347
    },
    {
      "product": "iphone_os",
      "vulnerability_count": 3208
    },
    {
      "product": "mac_os_x",
      "vulnerability_count": 3170
    },
    {
      "product": "windows_10",
      "vulnerability_count": 2938
    }
  ]
}
```


## GET `/query_attack_vectors`
Input parameter `topn` defines how many most common attack vectors should be returned.
From database both v2 and v3 metric attack vectors are queried (in v2 called access vectors).
If there is v3 then v2 is not used, if no v3 is present then v2 is used.
Returns top attack vectors and their occurrence counts combined for v3 and v2.

### Example request
``` 
curl -X 'GET' \
  'http://127.0.0.1:8000/query_attack_vectors?topn=10' \
  -H 'accept: application/json'
```

### Example response
```
{
  "attack_vectors": [
    {
      "attack_vector": "NETWORK",
      "attack_vector_count": 205169
    },
    {
      "attack_vector": "LOCAL",
      "attack_vector_count": 55217
    },
    {
      "attack_vector": "ADJACENT_NETWORK",
      "attack_vector_count": 7935
    },
    {
      "attack_vector": "PHYSICAL",
      "attack_vector_count": 2055
    }
  ]
}
```
