//
//  DescribedImageTests.swift
//
//
//  Created by Mark @ Germ on 7/22/26.
//

import CryptoKit
import Foundation
import Testing

@testable import CommProtocol

struct DescribedImageTests {
	@Test func testImageTypeRoundTrip() throws {
		for imageType in [ImageType.jpegXL, .jpeg] {
			let described = DescribedImage(
				imageType: imageType,
				imageData: SymmetricKey(size: .bits256).rawRepresentation,
				altText: "description"
			)
			let received = try DescribedImage.finalParse(described.wireFormat)
			#expect(received == described)
			#expect(received.imageType == imageType)
		}
	}

	@Test func testUnknownImageTypeRejected() throws {
		let described = DescribedImage(
			imageType: .jpeg,
			imageData: SymmetricKey(size: .bits256).rawRepresentation,
			altText: nil
		)
		var encoded = try described.wireFormat
		#expect(encoded.first == ImageType.jpeg.rawValue)
		encoded[encoded.startIndex] = 3

		#expect(throws: LinearEncodingError.unexpectedData) {
			_ = try DescribedImage.finalParse(encoded)
		}
	}

	@Test func testDetectJXLCodestream() {
		let data = Data([0xFF, 0x0A]) + Data(repeating: 0, count: 16)
		#expect(ImageType.detect(from: data) == .jpegXL)
	}

	@Test func testDetectJXLContainer() {
		let box: [UInt8] = [0, 0, 0, 0x0C, 0x4A, 0x58, 0x4C, 0x20, 0x0D, 0x0A, 0x87, 0x0A]
		let data = Data(box) + Data(repeating: 0, count: 16)
		#expect(ImageType.detect(from: data) == .jpegXL)
	}

	@Test func testDetectJPEG() {
		let data = Data([0xFF, 0xD8, 0xFF, 0xE0]) + Data(repeating: 0, count: 16)
		#expect(ImageType.detect(from: data) == .jpeg)
	}

	@Test func testDetectRejectsOther() {
		//PNG magic
		#expect(ImageType.detect(from: Data([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A])) == nil)
		#expect(ImageType.detect(from: Data()) == nil)
		#expect(ImageType.detect(from: Data([0xFF])) == nil)
	}

	///The compatibility posture: a sender without a JPEG XL encoder labels its
	///JPEG bytes `.jpegXL`; detection recovers the true format from the bytes.
	@Test func testFalseLabelRecoveredByDetection() {
		let jpegBytes = Data([0xFF, 0xD8, 0xFF, 0xE0]) + Data(repeating: 0, count: 16)
		let described = DescribedImage(
			imageData: jpegBytes,
			altText: nil
		)
		//wire label says jpegXL (the default)
		#expect(described.imageType == .jpegXL)
		//bytes say jpeg
		#expect(ImageType.detect(from: jpegBytes) == .jpeg)
	}
}
