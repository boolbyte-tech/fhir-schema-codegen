# WARNING: This file is autogenerated by FHIR Schema Codegen.
# https://github.com/fhir-schema/fhir-schema-codegen
# Any manual changes made to this file may be overwritten.

from __future__ import annotations
from pydantic import *
from typing import Optional, List as L, Literal

from .base import *
from .domain_resource import DomainResource


class PractitionerRoleAvailableTime(BackboneElement):
    all_day: Optional[bool] = None
    available_end_time: Optional[str] = None
    available_start_time: Optional[str] = None
    days_of_week: Optional[L[Literal["mon", "tue", "wed", "thu", "fri", "sat", "sun"]]] = None

class PractitionerRoleNotAvailable(BackboneElement):
    description: Optional[str] = None
    during: Optional[Period] = None


class PractitionerRole(DomainResource):
    active: Optional[bool] = None
    availability_exceptions: Optional[str] = None
    available_time: Optional[L[PractitionerRoleAvailableTime]] = None
    code: Optional[L[CodeableConcept]] = None
    endpoint: Optional[L[Reference]] = None
    healthcare_service: Optional[L[Reference]] = None
    identifier: Optional[L[Identifier]] = None
    location: Optional[L[Reference]] = None
    not_available: Optional[L[PractitionerRoleNotAvailable]] = None
    organization: Optional[Reference] = None
    period: Optional[Period] = None
    practitioner: Optional[Reference] = None
    specialty: Optional[L[CodeableConcept]] = None
    telecom: Optional[L[ContactPoint]] = None

