import Foundation

// MARK: - MitreTechnique
// Single source of truth. The duplicate file (same content, different timestamp)
// caused an "invalid redeclaration" error — keep only this one in the project.

enum MitreTechnique: String, Codable, Hashable, Sendable {
    // Existing
    case commandAndScriptingInterpreter = "T1059"
    case applicationLayerProtocol       = "T1071"
    case ingressToolTransfer            = "T1105"
    case bootOrLogonAutostartExecution  = "T1547"
    // Tier 3 additions
    case osCredentialDumping            = "T1003"
    case masquerading                   = "T1036"
    case processInjection               = "T1055"
    case systemInformationDiscovery     = "T1082"
    case impairDefenses                 = "T1562"
    // 3.0 — network intelligence layer
    case unsecuredCredentials           = "T1552"  // cleartext creds in traffic (NetworkMiner)
    case encryptedChannel               = "T1573"  // suspicious TLS (tshark/Zeek)

    var title: String {
        switch self {
        case .commandAndScriptingInterpreter: return "Command and Scripting Interpreter"
        case .applicationLayerProtocol:       return "Application Layer Protocol"
        case .ingressToolTransfer:            return "Ingress Tool Transfer"
        case .bootOrLogonAutostartExecution:  return "Boot or Logon Autostart Execution"
        case .osCredentialDumping:            return "OS Credential Dumping"
        case .masquerading:                   return "Masquerading"
        case .processInjection:               return "Process Injection"
        case .systemInformationDiscovery:     return "System Information Discovery"
        case .impairDefenses:                 return "Impair Defenses"
        case .unsecuredCredentials:           return "Unsecured Credentials"
        case .encryptedChannel:               return "Encrypted Channel"
        }
    }

    /// MITRE ATT&CK URL for this technique
    var referenceURL: URL {
        URL(string: "https://attack.mitre.org/techniques/\(rawValue)/")!
    }
}
