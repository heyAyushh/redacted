import Darwin
import Foundation
import FoundationModels

private let providerSchemaVersion = 1

@Generable
private struct ExtractedSpanCollection {
    @Guide(description: "Privacy-sensitive spans in the same order they appear in the input text. Return an empty array when nothing matches.")
    var spans: [ExtractedSpan]

    @Generable
    struct ExtractedSpan {
        @Guide(
            description: "One privacy label from the allowed list.",
            .anyOf([
                "account_number",
                "private_address",
                "private_date",
                "private_email",
                "private_person",
                "private_phone",
                "private_url",
                "secret",
            ])
        )
        var label: String

        @Guide(description: "The exact substring copied from the input text. Do not trim, normalize, or invent text.")
        var text: String
    }
}

private struct RequestPayload: Decodable {
    let schemaVersion: Int
    let requestID: String
    let text: String

    private enum CodingKeys: String, CodingKey {
        case schemaVersion = "schema_version"
        case requestID = "request_id"
        case text
    }
}

private struct ResponseSpan: Encodable {
    let label: String
    let start: Int
    let end: Int
}

private struct ResponsePayload: Encodable {
    let schemaVersion: Int
    let requestID: String
    let target: String
    let spans: [ResponseSpan]
    let error: String?

    private enum CodingKeys: String, CodingKey {
        case schemaVersion = "schema_version"
        case requestID = "request_id"
        case target
        case spans
        case error
    }
}

private enum RunnerError: Error {
    case invalidArguments(String)
    case invalidRequestSchema
    case invalidSpan
    case spanNotFound
}

@main
struct Main {
    static func main() async {
        do {
            let arguments = try parseArguments()
            if arguments.availabilityCheck {
                print(availabilityStatus())
                return
            }
            try await runService(target: arguments.target)
        } catch {
            fputs("apple-foundation-runner error: \(String(describing: error))\n", stderr)
            Darwin.exit(1)
        }
    }

    private static func runService(target: String) async throws {
        let decoder = JSONDecoder()
        let encoder = JSONEncoder()

        while let line = readLine() {
            if line.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                continue
            }

            var requestID: String
            let response: ResponsePayload
            do {
                let payload = try decoder.decode(RequestPayload.self, from: Data(line.utf8))
                requestID = payload.requestID
                guard payload.schemaVersion == providerSchemaVersion else {
                    throw RunnerError.invalidRequestSchema
                }
                let spans = try await detectSpans(in: payload.text)
                response = ResponsePayload(
                    schemaVersion: providerSchemaVersion,
                    requestID: requestID,
                    target: target,
                    spans: spans,
                    error: nil
                )
            } catch {
                requestID = bestEffortRequestID(from: line) ?? "unknown"
                response = ResponsePayload(
                    schemaVersion: providerSchemaVersion,
                    requestID: requestID,
                    target: target,
                    spans: [],
                    error: "runtime error: \(errorName(error))"
                )
            }

            let encoded = try encoder.encode(response)
            FileHandle.standardOutput.write(encoded)
            FileHandle.standardOutput.write(Data("\n".utf8))
        }
    }

    private static func detectSpans(in text: String) async throws -> [ResponseSpan] {
        switch SystemLanguageModel.default.availability {
        case .available:
            break
        case .unavailable(.appleIntelligenceNotEnabled):
            throw RunnerError.invalidArguments("apple_intelligence_not_enabled")
        case .unavailable(.modelNotReady):
            throw RunnerError.invalidArguments("model_not_ready")
        case .unavailable(.deviceNotEligible):
            throw RunnerError.invalidArguments("device_not_eligible")
        case .unavailable(let reason):
            throw RunnerError.invalidArguments("unavailable_\(String(describing: reason))")
        }

        if text.isEmpty {
            return []
        }

        let instructions = """
        You extract privacy-sensitive spans from input text.
        Return only exact substrings copied verbatim from the input.
        Do not trim, normalize, paraphrase, or invent any text.
        Sort spans by first appearance in the input.
        Treat a real person's full name as private_person.
        Treat street addresses as private_address.
        If the same sensitive substring appears multiple times, return one span entry for each occurrence in order.
        Use only these labels exactly:
        account_number, private_address, private_date, private_email, private_person, private_phone, private_url, secret.
        Return an empty spans array when nothing matches.
        """

        let session = LanguageModelSession(instructions: instructions)
        let options = GenerationOptions(temperature: 0)
        let prompt = """
        Example input:
        John Smith emailed john@example.com.
        Example spans:
        - private_person => John Smith
        - private_email => john@example.com

        Example input:
        Jane Doe lives at 18 Oak Avenue.
        Example spans:
        - private_person => Jane Doe
        - private_address => 18 Oak Avenue

        Example input:
        Jane Doe can be reached at jane@example.com. Jane Doe will reply soon.
        Example spans:
        - private_person => Jane Doe
        - private_email => jane@example.com
        - private_person => Jane Doe

        Example input:
        Call 555-123-4567 today.
        Example spans:
        - private_phone => 555-123-4567

        Now extract spans from this input text:
        \(text)
        """
        let result = try await session.respond(
            to: prompt,
            generating: ExtractedSpanCollection.self,
            options: options
        )
        return try alignSpans(in: text, spans: result.content.spans)
    }

    private static func alignSpans(
        in text: String,
        spans: [ExtractedSpanCollection.ExtractedSpan]
    ) throws -> [ResponseSpan] {
        let byteOffsets = characterToByteOffsets(in: text)
        var aligned: [ResponseSpan] = []

        for span in spans {
            guard !span.label.isEmpty, !span.text.isEmpty else {
                throw RunnerError.invalidSpan
            }

            let ranges = allRanges(for: span.text, in: text)
            guard !ranges.isEmpty else {
                throw RunnerError.spanNotFound
            }

            for range in ranges {
                let lowerDistance = text.distance(from: text.startIndex, to: range.lowerBound)
                let upperDistance = text.distance(from: text.startIndex, to: range.upperBound)
                aligned.append(
                    ResponseSpan(
                        label: span.label,
                        start: byteOffsets[lowerDistance],
                        end: byteOffsets[upperDistance]
                    )
                )
            }
        }

        return deduplicate(aligned).sorted {
            ($0.start, $0.end, $0.label) < ($1.start, $1.end, $1.label)
        }
    }

    private static func deduplicate(_ spans: [ResponseSpan]) -> [ResponseSpan] {
        var seen = Set<String>()
        var deduped: [ResponseSpan] = []
        for span in spans {
            let key = "\(span.label)|\(span.start)|\(span.end)"
            if seen.insert(key).inserted {
                deduped.append(span)
            }
        }
        return deduped
    }

    private static func allRanges(for snippet: String, in text: String) -> [Range<String.Index>] {
        var ranges: [Range<String.Index>] = []
        var searchStart = text.startIndex
        while searchStart < text.endIndex,
            let range = text.range(of: snippet, range: searchStart..<text.endIndex)
        {
            ranges.append(range)
            if range.lowerBound < range.upperBound {
                searchStart = range.upperBound
            } else {
                searchStart = text.index(after: searchStart)
            }
        }
        return ranges
    }

    private static func characterToByteOffsets(in text: String) -> [Int] {
        var offsets: [Int] = [0]
        var total = 0
        for character in text {
            total += String(character).lengthOfBytes(using: .utf8)
            offsets.append(total)
        }
        return offsets
    }

    private static func bestEffortRequestID(from line: String) -> String? {
        guard let range = line.range(of: "\"request_id\":\"") else {
            return nil
        }
        let suffix = line[range.upperBound...]
        guard let end = suffix.firstIndex(of: "\"") else {
            return nil
        }
        return String(suffix[..<end])
    }

    private static func errorName(_ error: Error) -> String {
        switch error {
        case let runnerError as RunnerError:
            return String(describing: runnerError)
        default:
            return String(describing: type(of: error))
        }
    }

    private static func availabilityStatus() -> String {
        switch SystemLanguageModel.default.availability {
        case .available:
            return "available"
        case .unavailable(.appleIntelligenceNotEnabled):
            return "unavailable:apple_intelligence_not_enabled"
        case .unavailable(.modelNotReady):
            return "unavailable:model_not_ready"
        case .unavailable(.deviceNotEligible):
            return "unavailable:device_not_eligible"
        case .unavailable(let reason):
            return "unavailable:\(String(describing: reason))"
        }
    }

    private static func parseArguments() throws -> (
        target: String,
        checkpoint: String?,
        availabilityCheck: Bool
    ) {
        var target: String?
        var checkpoint: String?
        var availabilityCheck = false

        var index = 1
        let arguments = CommandLine.arguments
        while index < arguments.count {
            switch arguments[index] {
            case "--target":
                index += 1
                guard index < arguments.count else {
                    throw RunnerError.invalidArguments("missing_target")
                }
                target = arguments[index]
            case "--checkpoint":
                index += 1
                guard index < arguments.count else {
                    throw RunnerError.invalidArguments("missing_checkpoint")
                }
                checkpoint = arguments[index]
            case "--availability-check":
                availabilityCheck = true
            default:
                throw RunnerError.invalidArguments("unknown_argument")
            }
            index += 1
        }

        if availabilityCheck {
            return (target ?? "apple/foundation-v1", checkpoint, true)
        }

        guard let target else {
            throw RunnerError.invalidArguments("missing_target")
        }
        guard checkpoint != nil else {
            throw RunnerError.invalidArguments("missing_checkpoint")
        }
        return (target, checkpoint, false)
    }
}
