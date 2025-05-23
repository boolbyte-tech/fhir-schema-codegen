
namespace Aidbox.FHIR.R4.Core;

public class SupplyRequest : DomainResource
{
    public CodeableConcept? Category { get; set; }
    public ResourceReference[]? Supplier { get; set; }
    public ResourceReference? DeliverTo { get; set; }
    public ResourceReference? ItemReference { get; set; }
    public CodeableConcept[]? ReasonCode { get; set; }
    public string? AuthoredOn { get; set; }
    public Timing? OccurrenceTiming { get; set; }
    public ResourceReference? DeliverFrom { get; set; }
    public ResourceReference? Requester { get; set; }
    public string? Priority { get; set; }
    public Period? OccurrencePeriod { get; set; }
    public string? Status { get; set; }
    public Identifier[]? Identifier { get; set; }
    public CodeableConcept? ItemCodeableConcept { get; set; }
    public Quantity? Quantity { get; set; }
    public string? OccurrenceDateTime { get; set; }
    public SupplyRequestParameter[]? Parameter { get; set; }
    public ResourceReference[]? ReasonReference { get; set; }
    
    public class SupplyRequestParameter : BackboneElement
    {
        public CodeableConcept? Code { get; set; }
        public CodeableConcept? ValueCodeableConcept { get; set; }
        public Quantity? ValueQuantity { get; set; }
        public Range? ValueRange { get; set; }
        public bool? ValueBoolean { get; set; }
    }
    
}

