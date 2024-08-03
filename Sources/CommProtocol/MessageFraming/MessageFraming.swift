//
//  MessageFraming.swift
//  CommProtocol
//
//  Created by Mark Xue on 7/28/24.
//

import Foundation

///Most of our wire objects are crytopgraphic objects (keys and signatures), which we can encode
///as fixed-width data prepended with a byte enum encoding the following type, and consequently the width,
///
///The structure is fairly predictable, so we can lay out these defined width chunks in a known order.
///
///We enclose flexible structures of undefined width (mostly string objects) as .utf8 JSON encoded data,
///prepended with a 2-byte wide counter, where the positions of these flexible width
///
///For our prefixes, we reserve 0 to indicate the absence of a subsequent value (Optional None)
///
///We can use one byte to denote an enum
///
///From outside to inside:
///# 0. Header encryption
///The entire MLS message is wrapped in a key derived from the current epoch
/// * welcome messages are HPKE basic encrypted
///# 1. MLS messages
///* We staple MLS messages together in the AD:
///[Application message [Update [Commit | Welcome]]
///# 2. Application Messages staple an application agent update
/// [Application Update][Application Content]

struct ApplicationUpdate {

}

enum ApplicationContent {
    case textMessage(AppTextMessage)
    //    case identityFollowup(IdentityFollowup)
}

struct AppTextMessage {
    public let body: String
    let threadId: UUID?
    let reference: UUID?
}
