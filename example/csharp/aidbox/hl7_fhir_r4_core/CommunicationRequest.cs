
namespace Aidbox.FHIR.R4.Core;

public class CommunicationRequest : DomainResource
{
    public CodeableConcept[]? Category { get; set; }
    public CommunicationRequestPayload[]? Payload { get; set; }
    public ResourceReference? Encounter { get; set; }
    public CodeableConcept[]? Medium { get; set; }
    public ResourceReference[]? Recipient { get; set; }
    public CodeableConcept[]? ReasonCode { get; set; }
    public CodeableConcept? StatusReason { get; set; }
    public string? AuthoredOn { get; set; }
    public Annotation[]? Note { get; set; }
    public ResourceReference? Requester { get; set; }
    public string? Priority { get; set; }
    public Period? OccurrencePeriod { get; set; }
    public string? Status { get; set; }
    public Identifier? GroupIdentifier { get; set; }
    public ResourceReference? Sender { get; set; }
    public Identifier[]? Identifier { get; set; }
    public bool? DoNotPerform { get; set; }
    public ResourceReference[]? Replaces { get; set; }
    public ResourceReference[]? BasedOn { get; set; }
    public string? OccurrenceDateTime { get; set; }
    public ResourceReference? Subject { get; set; }
    public ResourceReference[]? About { get; set; }
    public ResourceReference[]? ReasonReference { get; set; }
    
    public class CommunicationRequestPayload : BackboneElement
    {
        public string? ContentString { get; set; }
        public Attachment? ContentAttachment { get; set; }
        public ResourceReference? ContentReference { get; set; }
    }
    
}

