
namespace Aidbox.FHIR.R4.Core;

public class ActivityDefinition : DomainResource
{
    public ResourceReference[]? ObservationResultRequirement { get; set; }
    public Range? TimingRange { get; set; }
    public string? Description { get; set; }
    public string? Date { get; set; }
    public string? Transform { get; set; }
    public ContactDetail[]? Endorser { get; set; }
    public string? Publisher { get; set; }
    public string? ApprovalDate { get; set; }
    public CodeableConcept[]? Jurisdiction { get; set; }
    public Dosage[]? Dosage { get; set; }
    public ResourceReference[]? ObservationRequirement { get; set; }
    public string? Purpose { get; set; }
    public CodeableConcept? SubjectCodeableConcept { get; set; }
    public CodeableConcept? ProductCodeableConcept { get; set; }
    public string? Name { get; set; }
    public ResourceReference? ProductReference { get; set; }
    public Period? TimingPeriod { get; set; }
    public UsageContext[]? UseContext { get; set; }
    public string? Copyright { get; set; }
    public bool? Experimental { get; set; }
    public CodeableConcept[]? Topic { get; set; }
    public ActivityDefinitionParticipant[]? Participant { get; set; }
    public string? Title { get; set; }
    public string[]? Library { get; set; }
    public ContactDetail[]? Author { get; set; }
    public string? TimingDateTime { get; set; }
    public Timing? TimingTiming { get; set; }
    public string? Usage { get; set; }
    public Duration? TimingDuration { get; set; }
    public string? Priority { get; set; }
    public string? Status { get; set; }
    public string? Subtitle { get; set; }
    public string? Kind { get; set; }
    public ActivityDefinitionDynamicValue[]? DynamicValue { get; set; }
    public string? Url { get; set; }
    public CodeableConcept? Code { get; set; }
    public Identifier[]? Identifier { get; set; }
    public string? LastReviewDate { get; set; }
    public ContactDetail[]? Editor { get; set; }
    public bool? DoNotPerform { get; set; }
    public CodeableConcept[]? BodySite { get; set; }
    public Age? TimingAge { get; set; }
    public string? Intent { get; set; }
    public ResourceReference[]? SpecimenRequirement { get; set; }
    public ContactDetail[]? Reviewer { get; set; }
    public Quantity? Quantity { get; set; }
    public string? Version { get; set; }
    public RelatedArtifact[]? RelatedArtifact { get; set; }
    public ResourceReference? Location { get; set; }
    public ContactDetail[]? Contact { get; set; }
    public ResourceReference? SubjectReference { get; set; }
    public string? Profile { get; set; }
    public Period? EffectivePeriod { get; set; }
    
    public class ActivityDefinitionParticipant : BackboneElement
    {
        public string? Type { get; set; }
        public CodeableConcept? Role { get; set; }
    }
    
    public class ActivityDefinitionDynamicValue : BackboneElement
    {
        public string? Path { get; set; }
        public ResourceExpression? Expression { get; set; }
    }
    
}

