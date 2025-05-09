
namespace Aidbox.FHIR.R4.Core;

public class PlanDefinition : DomainResource
{
    public string? Description { get; set; }
    public string? Date { get; set; }
    public ContactDetail[]? Endorser { get; set; }
    public string? Publisher { get; set; }
    public string? ApprovalDate { get; set; }
    public CodeableConcept[]? Jurisdiction { get; set; }
    public string? Purpose { get; set; }
    public CodeableConcept? SubjectCodeableConcept { get; set; }
    public string? Name { get; set; }
    public UsageContext[]? UseContext { get; set; }
    public PlanDefinitionGoal[]? Goal { get; set; }
    public string? Copyright { get; set; }
    public CodeableConcept? Type { get; set; }
    public bool? Experimental { get; set; }
    public CodeableConcept[]? Topic { get; set; }
    public string? Title { get; set; }
    public string[]? Library { get; set; }
    public ContactDetail[]? Author { get; set; }
    public string? Usage { get; set; }
    public string? Status { get; set; }
    public string? Subtitle { get; set; }
    public string? Url { get; set; }
    public Identifier[]? Identifier { get; set; }
    public string? LastReviewDate { get; set; }
    public ContactDetail[]? Editor { get; set; }
    public PlanDefinitionAction[]? Action { get; set; }
    public ContactDetail[]? Reviewer { get; set; }
    public string? Version { get; set; }
    public RelatedArtifact[]? RelatedArtifact { get; set; }
    public ContactDetail[]? Contact { get; set; }
    public ResourceReference? SubjectReference { get; set; }
    public Period? EffectivePeriod { get; set; }
    
    public class PlanDefinitionGoalTarget : BackboneElement
    {
        public CodeableConcept? Measure { get; set; }
        public Quantity? DetailQuantity { get; set; }
        public Range? DetailRange { get; set; }
        public CodeableConcept? DetailCodeableConcept { get; set; }
        public Duration? Due { get; set; }
    }
    
    public class PlanDefinitionGoal : BackboneElement
    {
        public CodeableConcept? Category { get; set; }
        public CodeableConcept? Description { get; set; }
        public CodeableConcept? Priority { get; set; }
        public CodeableConcept? Start { get; set; }
        public CodeableConcept[]? Addresses { get; set; }
        public RelatedArtifact[]? Documentation { get; set; }
        public PlanDefinitionGoalTarget[]? Target { get; set; }
    }
    
    public class PlanDefinitionActionRelatedAction : BackboneElement
    {
        public string? ActionId { get; set; }
        public string? Relationship { get; set; }
        public Duration? OffsetDuration { get; set; }
        public Range? OffsetRange { get; set; }
    }
    
    public class PlanDefinitionActionParticipant : BackboneElement
    {
        public string? Type { get; set; }
        public CodeableConcept? Role { get; set; }
    }
    
    public class PlanDefinitionActionCondition : BackboneElement
    {
        public string? Kind { get; set; }
        public ResourceExpression? Expression { get; set; }
    }
    
    public class PlanDefinitionActionDynamicValue : BackboneElement
    {
        public string? Path { get; set; }
        public ResourceExpression? Expression { get; set; }
    }
    
    public class PlanDefinitionAction : BackboneElement
    {
        public Range? TimingRange { get; set; }
        public string? Description { get; set; }
        public string? Transform { get; set; }
        public string? TextEquivalent { get; set; }
        public string? DefinitionUri { get; set; }
        public string[]? GoalId { get; set; }
        public CodeableConcept? SubjectCodeableConcept { get; set; }
        public Period? TimingPeriod { get; set; }
        public string? DefinitionCanonical { get; set; }
        public PlanDefinitionActionRelatedAction[]? RelatedAction { get; set; }
        public CodeableConcept? Type { get; set; }
        public PlanDefinitionActionParticipant[]? Participant { get; set; }
        public DataRequirement[]? Output { get; set; }
        public string? Title { get; set; }
        public RelatedArtifact[]? Documentation { get; set; }
        public string? Prefix { get; set; }
        public string? SelectionBehavior { get; set; }
        public CodeableConcept[]? Reason { get; set; }
        public string? TimingDateTime { get; set; }
        public Timing? TimingTiming { get; set; }
        public Duration? TimingDuration { get; set; }
        public string? Priority { get; set; }
        public string? RequiredBehavior { get; set; }
        public PlanDefinitionActionCondition[]? Condition { get; set; }
        public string? GroupingBehavior { get; set; }
        public PlanDefinitionActionDynamicValue[]? DynamicValue { get; set; }
        public CodeableConcept[]? Code { get; set; }
        public Age? TimingAge { get; set; }
        public PlanDefinitionAction[]? Action { get; set; }
        public string? PrecheckBehavior { get; set; }
        public DataRequirement[]? Input { get; set; }
        public TriggerDefinition[]? Trigger { get; set; }
        public ResourceReference? SubjectReference { get; set; }
        public string? CardinalityBehavior { get; set; }
    }
    
}

