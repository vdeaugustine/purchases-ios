//
//  Copyright RevenueCat Inc. All Rights Reserved.
//
//  Licensed under the MIT License (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//
//      https://opensource.org/licenses/MIT
//
//  Signing+ResponseVerification.swift
//
//  Created by Nacho Soto on 2/8/23.

import Foundation

extension HTTPResponse where Body == Data {

    func verify(
        request: HTTPRequest,
        publicKey: Signing.PublicKey?,
        signing: SigningType.Type = Signing.self
    ) -> VerifiedHTTPResponse<Body> {
        let verificationResult = Self.verificationResult(
            body: self.body,
            statusCode: self.statusCode,
            headers: self.responseHeaders,
            requestDate: self.requestDate,
            request: request,
            publicKey: publicKey,
            signing: signing
        )

        #if DEBUG
        if verificationResult == .failed, ProcessInfo.isRunningRevenueCatTests {
            Logger.warn(Strings.signing.invalid_signature_data(
                request,
                self.body,
                self.responseHeaders,
                statusCode
            ))
        }
        #endif

        return self.verified(with: verificationResult)
    }

    // swiftlint:disable:next function_parameter_count
    private static func verificationResult(
        body: Data,
        statusCode: HTTPStatusCode,
        headers: HTTPClient.ResponseHeaders,
        requestDate: Date?,
        request: HTTPRequest,
        publicKey: Signing.PublicKey?,
        signing: SigningType.Type
    ) -> VerificationResult {
        guard let publicKey = publicKey,
              statusCode.isSuccessfulResponse,
              #available(iOS 13.0, macOS 10.15, tvOS 13.0, watchOS 6.2, *) else {
            return .notRequested
        }

        guard let _ = HTTPResponse.value(
            forCaseInsensitiveHeaderField: HTTPClient.ResponseHeader.signature.rawValue,
            in: headers
        ) else {
            let signatureRequested = request.nonce != nil
            if signatureRequested {
                Logger.warn(Strings.signing.signature_was_requested_but_not_provided(request))
                return .failed
            } else {
                return .notRequested
            }
        }

        guard let requestDate = requestDate else {
            Logger.warn(Strings.signing.request_date_missing_from_headers(request))

            return .failed
        }

        let result = TimingUtil.measureSyncAndLogIfTooSlow(
            threshold: .signatureVerification,
            message: Strings.signing.verification_too_slow,
            level: .error
        ) {
            for _ in 0..<1000 {
                _ = signing.verify(
                    signature: "nVoKJjLhhTNo19Mkjr5DEmgMf361HWxxMyctC10Ob7f/////+GStaG6mLGXfe+T+p6jDqBkuLHfF3VaCOYLwpCfWQBzeTGXB7ntSs4ESiw9sxHy0VTR0P5mSDxkSteR/qAANCFfQSkHeWl4NJ4IDusH1ieiZRfOpGr3lKo8gfwfJwpki/fa6wAyodzPrIBOD6Z0X6kBF+cPBTP6iwUVehqtCtHwYZA5f8HjZN77UVhwuWVIM",
                    with: .init(
                        message: body,
                        nonce: request.nonce,
                        requestDate: requestDate.millisecondsSince1970
                    ),
                    publicKey: publicKey
                )
            }

            return signing.verify(
                signature: "nVoKJjLhhTNo19Mkjr5DEmgMf361HWxxMyctC10Ob7f/////+GStaG6mLGXfe+T+p6jDqBkuLHfF3VaCOYLwpCfWQBzeTGXB7ntSs4ESiw9sxHy0VTR0P5mSDxkSteR/qAANCFfQSkHeWl4NJ4IDusH1iehUgiku0dMOx5+u53eU3eB45bV7Uttc/AX9bSzpwinw1hqRpuNOyNZOQk0r+vDokRcMlC9XgraztIAO+m0LLtMF",
                with: .init(
                    message: body,
                    nonce: request.nonce,
                    requestDate: requestDate.millisecondsSince1970
                ),
                publicKey: publicKey
            )
        }

        return result
            ? .verified
            : .failed
    }

}
