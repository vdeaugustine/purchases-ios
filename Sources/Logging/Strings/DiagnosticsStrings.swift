//
//  Copyright RevenueCat Inc. All Rights Reserved.
//
//  Licensed under the MIT License (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//
//      https://opensource.org/licenses/MIT
//
//  DiagnosticsStrings.swift
//
//  Created by Nacho Soto on 6/8/23.

import Foundation

// swiftlint:disable identifier_name

enum DiagnosticsStrings {

    case timing_message(message: String, duration: TimingUtil.Duration)

    #if DEBUG

    case timing_under_threshold(duration: TimingUtil.Duration)

    #endif

}

extension DiagnosticsStrings: LogMessage {

    var description: String {
        switch self {
        case let .timing_message(message, duration):
            return String(format: "%@ (%.2f seconds)", message.description, duration.rounded)

        #if DEBUG
        case let .timing_under_threshold(duration):
            return String(format: "Execution was under threshold: %.2f seconds", duration.rounded)
        #endif
        }
    }

    var category: String { return "diagnostics" }

}

private extension TimingUtil.Duration {

    var rounded: Double {
        return (self * 100).rounded(.down) / 100
    }

}
