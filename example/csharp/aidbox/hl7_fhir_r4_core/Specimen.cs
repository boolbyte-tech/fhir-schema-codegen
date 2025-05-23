
namespace Aidbox.FHIR.R4.Core;

public class Specimen : DomainResource
{
    public ResourceReference[]? Request { get; set; }
    public string? ReceivedTime { get; set; }
    public SpecimenProcessing[]? Processing { get; set; }
    public ResourceReference[]? Parent { get; set; }
    public CodeableConcept? Type { get; set; }
    public Annotation[]? Note { get; set; }
    public string? Status { get; set; }
    public CodeableConcept[]? Condition { get; set; }
    public SpecimenContainer[]? Container { get; set; }
    public Identifier[]? Identifier { get; set; }
    public Identifier? AccessionIdentifier { get; set; }
    public SpecimenCollection? Collection { get; set; }
    public ResourceReference? Subject { get; set; }
    
    public class SpecimenProcessing : BackboneElement
    {
        public string? Description { get; set; }
        public CodeableConcept? Procedure { get; set; }
        public ResourceReference[]? Additive { get; set; }
        public string? TimeDateTime { get; set; }
        public Period? TimePeriod { get; set; }
    }
    
    public class SpecimenContainer : BackboneElement
    {
        public Identifier[]? Identifier { get; set; }
        public string? Description { get; set; }
        public CodeableConcept? Type { get; set; }
        public Quantity? Capacity { get; set; }
        public Quantity? SpecimenQuantity { get; set; }
        public CodeableConcept? AdditiveCodeableConcept { get; set; }
        public ResourceReference? AdditiveReference { get; set; }
    }
    
    public class SpecimenCollection : BackboneElement
    {
        public string? CollectedDateTime { get; set; }
        public CodeableConcept? FastingStatusCodeableConcept { get; set; }
        public CodeableConcept? Method { get; set; }
        public Duration? FastingStatusDuration { get; set; }
        public Duration? Duration { get; set; }
        public ResourceReference? Collector { get; set; }
        public CodeableConcept? BodySite { get; set; }
        public Quantity? Quantity { get; set; }
        public Period? CollectedPeriod { get; set; }
    }
    
}

