# WARNING: This file is autogenerated by FHIR Schema Codegen.
# https://github.com/fhir-schema/fhir-schema-codegen
# Any manual changes made to this file may be overwritten.

from __future__ import annotations
from pydantic import *
from typing import Optional, List as L, Literal

from .base import *
from .domain_resource import DomainResource


class MedicinalProductManufacturingBusinessOperation(BackboneElement):
    authorisation_reference_number: Optional[Identifier] = None
    confidentiality_indicator: Optional[CodeableConcept] = None
    effective_date: Optional[str] = None
    manufacturer: Optional[L[Reference]] = None
    operation_type: Optional[CodeableConcept] = None
    regulator: Optional[Reference] = None

class MedicinalProductNameNamePart(BackboneElement):
    part: Optional[str] = None
    type: Optional[Coding] = None

class MedicinalProductNameCountryLanguage(BackboneElement):
    country: Optional[CodeableConcept] = None
    jurisdiction: Optional[CodeableConcept] = None
    language: Optional[CodeableConcept] = None

class MedicinalProductName(BackboneElement):
    country_language: Optional[L[MedicinalProductNameCountryLanguage]] = None
    name_part: Optional[L[MedicinalProductNameNamePart]] = None
    product_name: Optional[str] = None

class MedicinalProductSpecialDesignation(BackboneElement):
    date: Optional[str] = None
    identifier: Optional[L[Identifier]] = None
    indication_codeable_concept: Optional[CodeableConcept] = None
    indication_reference: Optional[Reference] = None
    intended_use: Optional[CodeableConcept] = None
    species: Optional[CodeableConcept] = None
    status: Optional[CodeableConcept] = None
    type: Optional[CodeableConcept] = None


class MedicinalProduct(DomainResource):
    additional_monitoring_indicator: Optional[CodeableConcept] = None
    attached_document: Optional[L[Reference]] = None
    clinical_trial: Optional[L[Reference]] = None
    combined_pharmaceutical_dose_form: Optional[CodeableConcept] = None
    contact: Optional[L[Reference]] = None
    cross_reference: Optional[L[Identifier]] = None
    domain: Optional[Coding] = None
    identifier: Optional[L[Identifier]] = None
    legal_status_of_supply: Optional[CodeableConcept] = None
    manufacturing_business_operation: Optional[L[MedicinalProductManufacturingBusinessOperation]] = None
    marketing_status: Optional[L[MarketingStatus]] = None
    master_file: Optional[L[Reference]] = None
    name: Optional[L[MedicinalProductName]] = None
    packaged_medicinal_product: Optional[L[Reference]] = None
    paediatric_use_indicator: Optional[CodeableConcept] = None
    pharmaceutical_product: Optional[L[Reference]] = None
    product_classification: Optional[L[CodeableConcept]] = None
    special_designation: Optional[L[MedicinalProductSpecialDesignation]] = None
    special_measures: Optional[L[str]] = None
    type: Optional[CodeableConcept] = None

