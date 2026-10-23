/**
 * CycloneDX v1.6 Cryptographic Bill of Materials (CBOM) Types
 * Compliant with ECMA-424 & CycloneDX v1.6 JSON Schema Specification
 */

export interface CycloneDXCBOM {
  bomFormat: 'CycloneDX';
  specVersion: '1.6';
  serialNumber: string;
  version: number;
  metadata: CBOMMetadata;
  components: CBOMComponent[];
  dependencies?: CBOMDependency[];
  vulnerabilities?: CBOMVulnerability[];
}

export interface CBOMMetadata {
  timestamp: string;
  tools: {
    components: Array<{
      type: 'application';
      author?: string;
      name: string;
      version: string;
      description?: string;
    }>;
  };
  component?: {
    type: 'application' | 'framework' | 'library' | 'file';
    name: string;
    version?: string;
  };
  properties?: Array<{
    name: string;
    value: string;
  }>;
}

export interface CBOMComponent {
  type: 'cryptographic-asset';
  'bom-ref': string;
  name: string;
  version?: string;
  description?: string;
  cryptoProperties: CBOMCryptoProperties;
  evidence?: {
    occurrences: Array<{
      location: string;
      line: number;
      offset: number;
      symbol?: string;
      additionalContext?: string;
    }>;
  };
  properties?: Array<{
    name: string;
    value: string;
  }>;
}

export interface CBOMCryptoProperties {
  assetType: 'algorithm' | 'certificate' | 'key' | 'protocol' | 'related-crypto-material';
  algorithmProperties?: CBOMAlgorithmProperties;
  certificateProperties?: CBOMCertificateProperties;
  protocolProperties?: CBOMProtocolProperties;
  oid?: string;
}

export interface CBOMAlgorithmProperties {
  primitive:
    | 'kem'
    | 'signature'
    | 'key-exchange'
    | 'block-cipher'
    | 'hash'
    | 'mac'
    | 'pke'
    | 'stream-cipher'
    | 'ae';
  parameterSetIdentifier?: string;
  curve?: string;
  executionEnvironment?: 'software-plain' | 'software-enclave' | 'hardware';
  implementationPlatform?: 'generic' | 'x86_64' | 'arm64';
  certificationLevel?: 'none' | 'fips140-2' | 'fips140-3' | 'cnsa-2.0';
  cryptoFunctions?: Array<
    | 'key-agree'
    | 'sign'
    | 'verify'
    | 'encrypt'
    | 'decrypt'
    | 'digest'
    | 'generate'
    | 'derive'
  >;
  classicalSecurityLevel?: number;
  nistQuantumSecurityLevel?: number;
}

export interface CBOMCertificateProperties {
  subjectName?: string;
  issuerName?: string;
  notValidBefore?: string;
  notValidAfter?: string;
  signatureAlgorithmRef?: string;
  subjectPublicKeyRef?: string;
  certificateFormat?: 'X.509' | 'PEM' | 'DER';
}

export interface CBOMProtocolProperties {
  type?: 'tls' | 'ssh' | 'ipsec' | 'custom';
  version?: string;
  cipherSuites?: string[];
  ikeVersions?: string[];
}

export interface CBOMDependency {
  ref: string;
  dependsOn: string[];
}

export interface CBOMVulnerability {
  'bom-ref': string;
  id: string;
  source?: {
    name: string;
    url?: string;
  };
  description: string;
  detail: string;
  recommendation?: string;
  ratings?: Array<{
    source?: { name: string };
    score?: number;
    severity?: 'critical' | 'high' | 'medium' | 'low' | 'info';
    method?: 'CVSSv31' | 'CVSSv4' | 'other';
  }>;
  affects: Array<{
    ref: string;
  }>;
}
