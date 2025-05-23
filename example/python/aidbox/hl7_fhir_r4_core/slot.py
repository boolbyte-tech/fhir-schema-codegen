# WARNING: This file is autogenerated by FHIR Schema Codegen.
# https://github.com/fhir-schema/fhir-schema-codegen
# Any manual changes made to this file may be overwritten.

from __future__ import annotations
from pydantic import *
from typing import Optional, List as L, Literal

from .base import *
from .domain_resource import DomainResource


class Slot(DomainResource):
    appointment_type: Optional[CodeableConcept] = None
    comment: Optional[str] = None
    end: Optional[str] = None
    identifier: Optional[L[Identifier]] = None
    overbooked: Optional[bool] = None
    schedule: Optional[Reference] = None
    service_category: Optional[L[CodeableConcept]] = None
    service_type: Optional[L[CodeableConcept]] = None
    specialty: Optional[L[CodeableConcept]] = None
    start: Optional[str] = None
    status: Optional[Literal["busy", "free", "busy-unavailable", "busy-tentative", "entered-in-error"]] = None

