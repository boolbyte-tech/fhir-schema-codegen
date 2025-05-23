# WARNING: This file is autogenerated by FHIR Schema Codegen.
# https://github.com/fhir-schema/fhir-schema-codegen
# Any manual changes made to this file may be overwritten.

from __future__ import annotations
from pydantic import *
from typing import Optional, List as L, Literal

from .base import *
from .domain_resource import DomainResource


class DeviceDeviceName(BackboneElement):
    name: Optional[str] = None
    type: Optional[Literal["udi-label-name", "user-friendly-name", "patient-reported-name", "manufacturer-name", "model-name", "other"]] = None

class DeviceProperty(BackboneElement):
    type: Optional[CodeableConcept] = None
    value_code: Optional[L[CodeableConcept]] = None
    value_quantity: Optional[L[Quantity]] = None

class DeviceSpecialization(BackboneElement):
    system_type: Optional[CodeableConcept] = None
    version: Optional[str] = None

class DeviceVersion(BackboneElement):
    component: Optional[Identifier] = None
    type: Optional[CodeableConcept] = None
    value: Optional[str] = None

class DeviceUdiCarrier(BackboneElement):
    carrier_aidc: Optional[str] = None
    carrier_hrf: Optional[str] = None
    device_identifier: Optional[str] = None
    entry_type: Optional[Literal["barcode", "rfid", "manual", "card", "self-reported", "unknown"]] = None
    issuer: Optional[str] = None
    jurisdiction: Optional[str] = None


class Device(DomainResource):
    contact: Optional[L[ContactPoint]] = None
    definition: Optional[Reference] = None
    device_name: Optional[L[DeviceDeviceName]] = None
    distinct_identifier: Optional[str] = None
    expiration_date: Optional[str] = None
    identifier: Optional[L[Identifier]] = None
    location: Optional[Reference] = None
    lot_number: Optional[str] = None
    manufacture_date: Optional[str] = None
    manufacturer: Optional[str] = None
    model_number: Optional[str] = None
    note: Optional[L[Annotation]] = None
    owner: Optional[Reference] = None
    parent: Optional[Reference] = None
    part_number: Optional[str] = None
    patient: Optional[Reference] = None
    property: Optional[L[DeviceProperty]] = None
    safety: Optional[L[CodeableConcept]] = None
    serial_number: Optional[str] = None
    specialization: Optional[L[DeviceSpecialization]] = None
    status: Optional[Literal["active", "inactive", "entered-in-error", "unknown"]] = None
    status_reason: Optional[L[CodeableConcept]] = None
    type: Optional[CodeableConcept] = None
    udi_carrier: Optional[L[DeviceUdiCarrier]] = None
    url: Optional[str] = None
    version: Optional[L[DeviceVersion]] = None

