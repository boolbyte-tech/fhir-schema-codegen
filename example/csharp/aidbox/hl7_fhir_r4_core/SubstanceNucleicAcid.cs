
namespace Aidbox.FHIR.R4.Core;

public class SubstanceNucleicAcid : DomainResource
{
    public CodeableConcept? SequenceType { get; set; }
    public int? NumberOfSubunits { get; set; }
    public string? AreaOfHybridisation { get; set; }
    public CodeableConcept? OligoNucleotideType { get; set; }
    public SubstanceNucleicAcidSubunit[]? Subunit { get; set; }
    
    public class SubstanceNucleicAcidSubunitLinkage : BackboneElement
    {
        public string? Connectivity { get; set; }
        public Identifier? Identifier { get; set; }
        public string? Name { get; set; }
        public string? ResidueSite { get; set; }
    }
    
    public class SubstanceNucleicAcidSubunitSugar : BackboneElement
    {
        public Identifier? Identifier { get; set; }
        public string? Name { get; set; }
        public string? ResidueSite { get; set; }
    }
    
    public class SubstanceNucleicAcidSubunit : BackboneElement
    {
        public int? Subunit { get; set; }
        public string? Sequence { get; set; }
        public int? Length { get; set; }
        public Attachment? SequenceAttachment { get; set; }
        public CodeableConcept? FivePrime { get; set; }
        public CodeableConcept? ThreePrime { get; set; }
        public SubstanceNucleicAcidSubunitLinkage[]? Linkage { get; set; }
        public SubstanceNucleicAcidSubunitSugar[]? Sugar { get; set; }
    }
    
}

