
namespace Aidbox.FHIR.R4.Core;

public class Measure : DomainResource
{
    public string? Description { get; set; }
    public string[]? Definition { get; set; }
    public string? Date { get; set; }
    public MeasureGroup[]? Group { get; set; }
    public ContactDetail[]? Endorser { get; set; }
    public string? Publisher { get; set; }
    public string? ApprovalDate { get; set; }
    public CodeableConcept? CompositeScoring { get; set; }
    public string? Disclaimer { get; set; }
    public CodeableConcept[]? Jurisdiction { get; set; }
    public string? Purpose { get; set; }
    public CodeableConcept? SubjectCodeableConcept { get; set; }
    public string? Name { get; set; }
    public UsageContext[]? UseContext { get; set; }
    public string? Copyright { get; set; }
    public string? Guidance { get; set; }
    public CodeableConcept[]? Type { get; set; }
    public bool? Experimental { get; set; }
    public CodeableConcept[]? Topic { get; set; }
    public string? Title { get; set; }
    public MeasureSupplementalData[]? SupplementalData { get; set; }
    public string[]? Library { get; set; }
    public ContactDetail[]? Author { get; set; }
    public string? Usage { get; set; }
    public string? Rationale { get; set; }
    public string? Status { get; set; }
    public string? Subtitle { get; set; }
    public string? Url { get; set; }
    public Identifier[]? Identifier { get; set; }
    public string? LastReviewDate { get; set; }
    public ContactDetail[]? Editor { get; set; }
    public string? RiskAdjustment { get; set; }
    public CodeableConcept? Scoring { get; set; }
    public ContactDetail[]? Reviewer { get; set; }
    public string? Version { get; set; }
    public RelatedArtifact[]? RelatedArtifact { get; set; }
    public ContactDetail[]? Contact { get; set; }
    public ResourceReference? SubjectReference { get; set; }
    public CodeableConcept? ImprovementNotation { get; set; }
    public string? RateAggregation { get; set; }
    public Period? EffectivePeriod { get; set; }
    public string? ClinicalRecommendationStatement { get; set; }
    
    public class MeasureGroupPopulation : BackboneElement
    {
        public CodeableConcept? Code { get; set; }
        public string? Description { get; set; }
        public ResourceExpression? Criteria { get; set; }
    }
    
    public class MeasureGroupStratifierComponent : BackboneElement
    {
        public CodeableConcept? Code { get; set; }
        public string? Description { get; set; }
        public ResourceExpression? Criteria { get; set; }
    }
    
    public class MeasureGroupStratifier : BackboneElement
    {
        public CodeableConcept? Code { get; set; }
        public string? Description { get; set; }
        public ResourceExpression? Criteria { get; set; }
        public MeasureGroupStratifierComponent[]? Component { get; set; }
    }
    
    public class MeasureGroup : BackboneElement
    {
        public CodeableConcept? Code { get; set; }
        public string? Description { get; set; }
        public MeasureGroupPopulation[]? Population { get; set; }
        public MeasureGroupStratifier[]? Stratifier { get; set; }
    }
    
    public class MeasureSupplementalData : BackboneElement
    {
        public CodeableConcept? Code { get; set; }
        public CodeableConcept[]? Usage { get; set; }
        public string? Description { get; set; }
        public ResourceExpression? Criteria { get; set; }
    }
    
}

