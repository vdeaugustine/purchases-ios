//
//  Copyright RevenueCat Inc. All Rights Reserved.
//
//  Licensed under the MIT License (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//
//      https://opensource.org/licenses/MIT
//
//  SigningTests.swift
//
//  Created by Nacho Soto on 1/13/23.

import CryptoKit
import Nimble
import XCTest

@testable import RevenueCat

@available(iOS 13.0, macOS 10.15, tvOS 13.0, watchOS 6.2, *)
class SigningTests: TestCase {

    fileprivate typealias PrivateKey = Curve25519.Signing.PrivateKey
    fileprivate typealias PublicKey = Curve25519.Signing.PublicKey

    private let (privateKey, publicKey) = SigningTests.createRandomKey()

    override func setUpWithError() throws {
        try super.setUpWithError()

        try AvailabilityChecks.iOS13APIAvailableOrSkipTest()
    }

    func testLoadDefaultPublicKey() throws {
        let key = try XCTUnwrap(Signing.loadPublicKey() as? PublicKey)

        expect(key.rawRepresentation).toNot(beEmpty())
    }

    func testThrowsErrorIfPublicKeyFileCannotBeParsed() throws {
        expect {
            try Signing.loadPublicKey(with: .init([1, 2, 3]))
        }.to(throwError { error in
            expect(error).to(matchError(ErrorCode.configurationError))
            expect(error.localizedDescription) == "There is an issue with your configuration. " +
            "Check the underlying error for more details. Failed to load public key. " +
            "Ensure that it's a valid ed25519 key."
        })
    }

    func testVerifySignatureWithInvalidSignatureReturnsFalseAndLogsError() throws {
        let logger = TestLogHandler()

        let message = "Hello World"
        let nonce = "nonce"
        let requestDate: UInt64 = 1677005916012
        let signature = "this is not a signature"

        expect(Signing.verify(
            signature: signature,
            with: .init(
                message: message.asData,
                nonce: nonce.asData,
                requestDate: requestDate
            ),
            publicKey: Signing.loadPublicKey()
        )) == false

        logger.verifyMessageWasLogged("Signature is not base64: \(signature)")
    }

    func testVerifySignatureWithInvalidSignature() throws {
        expect(Signing.verify(
            signature: "invalid signature".asData.base64EncodedString(),
            with: .init(
                message: "Hello World".asData,
                nonce: "nonce".asData,
                requestDate: 1677005916012
            ),
            publicKey: Signing.loadPublicKey()
        )) == false
    }

    func testVerifySignatureLogsWarningWhenFail() throws {
        let logger = TestLogHandler()

        let signature = String(repeating: "x", count: Signing.SignatureComponent.totalSize)
            .asData

        _ = Signing.verify(signature: signature.base64EncodedString(),
                           with: .init(
                            message: "Hello World".asData,
                            nonce: "nonce".asData,
                            requestDate: 1677005916012
                           ),
                           publicKey: Signing.loadPublicKey())

        logger.verifyMessageWasLogged(Strings.signing.signature_failed_verification,
                                      level: .warn)
    }

    func testVerifySignatureLogsWarningWhenSizeIsIncorrect() throws {
        let logger = TestLogHandler()

        let signature = "invalid signature".asData

        _ = Signing.verify(signature: signature.base64EncodedString(),
                           with: .init(
                            message: "Hello World".asData,
                            nonce: "nonce".asData,
                            requestDate: 1677005916012
                           ),
                           publicKey: Signing.loadPublicKey())

        logger.verifyMessageWasLogged(Strings.signing.signature_invalid_size(signature),
                                      level: .warn)
    }

    func testVerifySignatureWithValidSignature() throws {
        let message = "Hello World"
        let nonce = "nonce"
        let requestDate: UInt64 = 1677005916012
        let publicKey = Self.createSignedPublicKey()
        let salt = Self.createSalt()

        let signature = try self.sign(
            parameters: .init(
                message: message.asData,
                nonce: nonce.asData,
                requestDate: requestDate
            ),
            salt: salt.asData
        )
        let fullSignature = Self.fullSignature(
            publicKey: publicKey,
            salt: salt,
            signature: signature
        )

        expect(Signing.verify(
            signature: fullSignature.base64EncodedString(),
            with: .init(
                message: message.asData,
                nonce: nonce.asData,
                requestDate: requestDate
            ),
            publicKey: self.publicKey
        )) == true
    }

    func testVerifyKnownSignatureWithNonce() throws {
        /*
         Signature retrieved with:
        curl -v 'https://api.revenuecat.com/v1/subscribers/login' \
        -X GET \
        -H 'X-Nonce: MTIzNDU2Nzg5MGFi' \
        -H 'Authorization: Bearer {api_key}'
         */

        // swiftlint:disable line_length
        let response = """
        {"request_date":"2023-06-22T19:28:22Z","request_date_ms":1687462102615,"subscriber":{"entitlements":{},"first_seen":"2023-06-22T19:28:22Z","last_seen":"2023-06-22T19:28:22Z","management_url":null,"non_subscriptions":{},"original_app_user_id":"login","original_application_version":null,"original_purchase_date":null,"other_purchases":{},"subscriptions":{}}}\n
        """
        let expectedSignature = "nVoKJjLhhTNo19Mkjr5DEmgMf361HWxxMyctC10Ob7f/////+GStaG6mLGXfe+T+p6jDqBkuLHfF3VaCOYLwpCfWQBzeTGXB7ntSs4ESiw9sxHy0VTR0P5mSDxkSteR/qAANCFfQSkHeWl4NJ4IDusH1ieiZRfOpGr3lKo8gfwfJwpki/fa6wAyodzPrIBOD6Z0X6kBF+cPBTP6iwUVehqtCtHwYZA5f8HjZN77UVhwuWVIM"
        // swiftlint:enable line_length

        let nonce = try XCTUnwrap(Data(base64Encoded: "MTIzNDU2Nzg5MGFi"))
        let requestDate: UInt64 = 1687455094309

        expect(
            Signing.verify(
                signature: expectedSignature,
                with: .init(
                    message: response.asData,
                    nonce: nonce,
                    requestDate: requestDate
                ),
                publicKey: Signing.loadPublicKey()
            )
        ) == true
    }

    func testVerifyKnownSignatureWithNoNonce() throws {
        /*
         Signature retrieved with:
        curl -v 'https://api.revenuecat.com/v1/subscribers/test/offerings' \
        -X GET \
        -H 'Authorization: Bearer {api_key}'
         */

        // swiftlint:disable line_length
        let response = """
        {"current_offering_id":"default","offerings":[{"description":"Default","identifier":"default","packages":[]}]}\n
        """
        let expectedSignature = "nVoKJjLhhTNo19Mkjr5DEmgMf361HWxxMyctC10Ob7f/////+GStaG6mLGXfe+T+p6jDqBkuLHfF3VaCOYLwpCfWQBzeTGXB7ntSs4ESiw9sxHy0VTR0P5mSDxkSteR/qAANCFfQSkHeWl4NJ4IDusH1iejcYPkhD3CLH6VyQHy5eBJ1axPdC5rbPsQngRNNGFEE/EC27ID8YbiG178yv+cQFNaDKDNuXI+AjVGYawHx9kkJ"
        // swiftlint:enable line_length

        let requestDate: UInt64 = 1687455094309

        expect(
            Signing.verify(
                signature: expectedSignature,
                with: .init(
                    message: response.asData,
                    nonce: nil,
                    requestDate: requestDate
                ),
                publicKey: Signing.loadPublicKey()
            )
        ) == true
    }

    func testVerifyKnownSignatureOfEmptyResponseWithNonce() throws {
        /*
         Signature retrieved with:
        curl -v 'https://api.revenuecat.com/v1/health' \
        -X GET \
        -H 'X-Nonce: MTIzNDU2Nzg5MGFi'
         */

        // swiftlint:disable line_length
        let response = "\"\"\n"
        let expectedSignature = "nVoKJjLhhTNo19Mkjr5DEmgMf361HWxxMyctC10Ob7f/////+GStaG6mLGXfe+T+p6jDqBkuLHfF3VaCOYLwpCfWQBzeTGXB7ntSs4ESiw9sxHy0VTR0P5mSDxkSteR/qAANCFfQSkHeWl4NJ4IDusH1iehUgiku0dMOx5+u53eU3eB45bV7Uttc/AX9bSzpwinw1hqRpuNOyNZOQk0r+vDokRcMlC9XgraztIAO+m0LLtMF"
        // swiftlint:enable line_length

        let nonce = try XCTUnwrap(Data(base64Encoded: "MTIzNDU2Nzg5MGFi"))
        let requestDate: UInt64 = 1687455094309

        expect(
            Signing.verify(
                signature: expectedSignature,
                with: .init(
                    message: response.asData,
                    nonce: nonce,
                    requestDate: requestDate
                ),
                publicKey: Signing.loadPublicKey()
            )
        ) == true
    }

    func testResponseVerificationWithNoProvidedKey() throws {
        let request = HTTPRequest.createWithResponseVerification(method: .get, path: .health)
        let response = HTTPResponse(statusCode: .success, responseHeaders: [:], body: Data())
        let verifiedResponse = response.verify(request: request, publicKey: nil)

        expect(verifiedResponse.verificationResult) == .notRequested
    }

    func testResponseVerificationWithNoSignatureInResponse() throws {
        let request = HTTPRequest.createWithResponseVerification(method: .get, path: .health)
        let logger = TestLogHandler()

        let response = HTTPResponse(statusCode: .success, responseHeaders: [:], body: Data())
        let verifiedResponse = response.verify(request: request, publicKey: self.publicKey)

        expect(verifiedResponse.verificationResult) == .failed

        logger.verifyMessageWasLogged(Strings.signing.signature_was_requested_but_not_provided(request),
                                      level: .warn)
    }

    func testResponseVerificationWithInvalidSignature() throws {
        let request = HTTPRequest.createWithResponseVerification(method: .get, path: .health)
        let response = HTTPResponse(
            statusCode: .success,
            responseHeaders: [
                HTTPClient.ResponseHeader.signature.rawValue: "invalid_signature"
            ],
            body: Data()
        )
        let verifiedResponse = response.verify(request: request, publicKey: self.publicKey)

        expect(verifiedResponse.verificationResult) == .failed
    }

    func testResponseVerificationWithNonceWithValidSignature() throws {
        let message = "Hello World"
        let nonce = "0123456789ab"
        let requestDate = Date().millisecondsSince1970
        let publicKey = Self.createSignedPublicKey()
        let salt = Self.createSalt()

        let signature = try self.sign(parameters: .init(message: message.asData,
                                                        nonce: nonce.asData,
                                                        requestDate: requestDate),
                                      salt: salt.asData)
        let fullSignature = Self.fullSignature(
            publicKey: publicKey,
            salt: salt,
            signature: signature
        )

        let request = HTTPRequest(method: .get, path: .health, nonce: nonce.asData)
        let response = HTTPResponse(
            statusCode: .success,
            responseHeaders: [
                HTTPClient.ResponseHeader.signature.rawValue: fullSignature.base64EncodedString(),
                HTTPClient.ResponseHeader.requestDate.rawValue: String(requestDate)
            ],
            body: message.asData
        )
        let verifiedResponse = response.verify(request: request, publicKey: self.publicKey)

        expect(verifiedResponse.verificationResult) == .verified
    }

    func testResponseVerificationWithoutNonceWithValidSignature() throws {
        let message = "Hello World"
        let requestDate = Date().millisecondsSince1970
        let publicKey = Self.createSignedPublicKey()
        let salt = Self.createSalt()

        let signature = try self.sign(parameters: .init(message: message.asData,
                                                        nonce: nil,
                                                        requestDate: requestDate),
                                      salt: salt.asData)
        let fullSignature = Self.fullSignature(
            publicKey: publicKey,
            salt: salt,
            signature: signature
        )

        let request = HTTPRequest(method: .get, path: .health, nonce: nil)
        let response = HTTPResponse(
            statusCode: .success,
            responseHeaders: [
                HTTPClient.ResponseHeader.signature.rawValue: fullSignature.base64EncodedString(),
                HTTPClient.ResponseHeader.requestDate.rawValue: String(requestDate)
            ],
            body: message.asData
        )
        let verifiedResponse = response.verify(request: request, publicKey: self.publicKey)

        expect(verifiedResponse.verificationResult) == .verified
    }

    func testResponseVerificationWithoutNonceAndNoSignatureReturnsNotRequested() throws {
        let message = "Hello World"
        let requestDate = Date().millisecondsSince1970

        let logger = TestLogHandler()

        let request = HTTPRequest(method: .get, path: .health, nonce: nil)
        let response = HTTPResponse(
            statusCode: .success,
            responseHeaders: [
                HTTPClient.ResponseHeader.requestDate.rawValue: String(requestDate)
            ],
            body: message.asData
        )
        let verifiedResponse = response.verify(request: request, publicKey: self.publicKey)

        expect(verifiedResponse.verificationResult) == .notRequested

        logger.verifyMessageWasNotLogged(Strings.signing.signature_was_requested_but_not_provided(request),
                                         allowNoMessages: true)
    }

}

@available(iOS 13.0, macOS 10.15, tvOS 13.0, watchOS 6.2, *)
private extension SigningTests {

    static func createRandomKey() -> (PrivateKey, PublicKey) {
        let key = PrivateKey()

        return (key, key.publicKey)
    }

    func sign(parameters: Signing.SignatureParameters, salt: Data) throws -> Data {
        return try self.sign(key: self.privateKey, parameters: parameters, salt: salt)
    }

    func sign(key: PrivateKey, parameters: Signing.SignatureParameters, salt: Data) throws -> Data {
        return try key.signature(for: salt + parameters.asData)
    }

    static func fullSignature(publicKey: String, salt: String, signature: Data) -> Data {
        return publicKey.asData + salt.asData + signature
    }

    static func createSalt() -> String {
        return Array(repeating: "a", count: Signing.SignatureComponent.salt.size).joined()
    }

    static func createSignedPublicKey() -> String {
        return Array(repeating: "b", count: Signing.SignatureComponent.signedPublicKeySize).joined()
    }

}
