
namespace Aidbox.FHIR.R4.Core;

public class Communication : DomainResource
{
    public CodeableConcept[]? Category { get; set; }
    public string? Received { get; set; }
    public string[]? InstantiatesCanonical { get; set; }
    public CommunicationPayload[]? Payload { get; set; }
    public string[]? InstantiatesUri { get; set; }
    public ResourceReference? Encounter { get; set; }
    public CodeableConcept[]? Medium { get; set; }
    public ResourceReference[]? Recipient { get; set; }
    public CodeableConcept[]? ReasonCode { get; set; }
    public CodeableConcept? StatusReason { get; set; }
    public CodeableConcept? Topic { get; set; }
    public string? Sent { get; set; }
    public Annotation[]? Note { get; set; }
    public string? Priority { get; set; }
    public string? Status { get; set; }
    public ResourceReference? Sender { get; set; }
    public Identifier[]? Identifier { get; set; }
    public ResourceReference[]? InResponseTo { get; set; }
    public ResourceReference[]? BasedOn { get; set; }
    public ResourceReference[]? PartOf { get; set; }
    public ResourceReference? Subject { get; set; }
    public ResourceReference[]? About { get; set; }
    public ResourceReference[]? ReasonReference { get; set; }
    
    public class CommunicationPayload : BackboneElement
    {
        public string? ContentString { get; set; }
        public Attachment? ContentAttachment { get; set; }
        public ResourceReference? ContentReference { get; set; }
    }
    
}

