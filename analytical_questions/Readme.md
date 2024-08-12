# Analytical Questions

Task: Answer at least three of the following analytical questions relevant to your selected
data.

Note - Make sure that you have data as of 05-01-2024, not including any data collected
after 05-01-2024 in analysis. I made an assumption that the date is represented in US format and
not European meaning 05-01-2024 corresponds to 1st of May 2024.

All the answers use  data for cvss_version 3 if its present else falling back to cvss_version 2.

I chose to answer questions 1., 2. and 5.

All the SQL queries are present in `analytical_questions_queries.sql`.

# 1. Severity Distribution
Task is to find what is the count of vulnerabilities for different severity
levels?

| BASE_SEVERITY | severity count |
|---------------|----------------|
| MEDIUM        | 102,702        |
| HIGH          | 87,241         |
| NULL          | 50,165         |
| CRITICAL      | 20,119         |
| LOW           | 10,130         |
| NONE          | 19             |


# 4. Worst Products and Platforms
Task is to find out the worst products, platforms with most number of known vulnerabilities.

According to the CVE documentation the product and platform can be extracted from CPE name.

Note that some vulnerabilities have vendor/product listed multiple times. In the queries we count the vendor/platform once per vulenrability to avoid duplication.

Results are displayed in the table

| vendor    | vulnerability count |
|-----------|---------------------|
| qualcomm  | 138,007             |
| intel     | 32,149              |
| dell      | 24,639              |
| hp        | 18,211              |
| cisco     | 16,077              |
| microsoft | 13,520              |
| google    | 10,760              |
| amd       | 10,753              |
| oracle    | 10,154              |
| netgear   | 10,003              |

| product            | vulnerability count |
|--------------------|---------------------|
| debian_linux       | 8,486               |
| android            | 6,848               |
| fedora             | 4,988               |
| ubuntu_linux       | 3,879               |
| linux_kernel       | 3,474               |
| chrome             | 3,352               |
| windows_server_2016 | 3,347              |
| iphone_os          | 3,208               |
| mac_os_x           | 3,170               |
| windows_10         | 2,938               |



# 5. Attack vectors 
Task is to list top 10 attack vectors used.

Variable "Attack Vector" is categorized into four main types in CVE API: Network, Adjacent, Local, Physical, therefore only 4 attack vectors are present in top 10.
Also, in version 2.0 the term "Access Vector" is used instead of "Attack Vector". In 3.0 and 3.1  "Attack Vector" is used. 


The top attack vectors are here

attack vector | count 
------------- | ------
NETWORK	| 205169
LOCAL |	55217
ADJACENT_NETWORK	| 7935
PHYSICAL	| 2055