from pydantic import BaseModel, Field
from datetime import datetime
from typing import Optional, List


class CVEItem(BaseModel):
    id: int
    cve_id_text: str
    metadata_id: int
    source_identifier: str
    published: datetime
    last_modified: datetime
    vuln_status: str


class CVEList(BaseModel):
    cve_list: List[CVEItem]


class SeverityItem(BaseModel):
    base_severity: Optional[str]
    severity_count: int


class SeverityList(BaseModel):
    severity_list: List[SeverityItem]


class VendorVulnerabilityItem(BaseModel):
    vendor: str
    vulnerability_count: int


class VendorVulnerabilityList(BaseModel):
    vendor_vulnerabilities: List[VendorVulnerabilityItem]


class ProductVulnerabilityItem(BaseModel):
    product: str
    vulnerability_count: int


class ProductVulnerabilityList(BaseModel):
    product_vulnerabilities: List[ProductVulnerabilityItem]


class AttackVectorItem(BaseModel):
    attack_vector: str
    attack_vector_count: int


class AttackVectorList(BaseModel):
    attack_vectors: List[AttackVectorItem]
