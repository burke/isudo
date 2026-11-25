import XCTest

/// The phone's half of `ios/e2e-watch.sh`: pair with a computer, then allow
/// this phone's watch to answer for it. Afterwards the app stays open, as
/// the courier for the watch's answers, until the script says it is done.
final class WatchEndToEndTests: XCTestCase {
    private func wait(for file: URL, timeout: TimeInterval) throws -> String {
        let deadline = Date().addingTimeInterval(timeout)
        while Date() < deadline {
            if let text = try? String(contentsOf: file, encoding: .utf8), !text.isEmpty {
                return text.trimmingCharacters(in: .whitespacesAndNewlines)
            }
            Thread.sleep(forTimeInterval: 0.25)
        }
        throw XCTSkip("\(file.lastPathComponent) never appeared")
    }

    @MainActor
    func testPairAndAllowWatch() throws {
        guard let path = ProcessInfo.processInfo.environment["ISUDO_E2E_DIR"] else {
            throw XCTSkip("run through ios/e2e-watch.sh")
        }
        // Each step depends on the one before.
        continueAfterFailure = false
        let directory = URL(filePath: path)
        func mark(_ name: String) throws {
            try name.write(to: directory.appending(path: name + ".txt"), atomically: true, encoding: .utf8)
        }
        let link = try wait(for: directory.appending(path: "link.txt"), timeout: 60)

        let app = XCUIApplication()
        app.launch()
        XCTAssertTrue(app.buttons["Pair a computer"].waitForExistence(timeout: 30))
        app.buttons["Pair a computer"].firstMatch.tap()
        let paste = app.buttons["Paste a pairing link instead"]
        XCTAssertTrue(paste.waitForExistence(timeout: 10))
        paste.tap()
        let field = app.alerts.textFields.firstMatch
        XCTAssertTrue(field.waitForExistence(timeout: 10))
        field.typeText(link)
        app.alerts.buttons["Pair"].tap()
        let agree = app.buttons["Pair with this computer"]
        XCTAssertTrue(agree.waitForExistence(timeout: 20))
        agree.tap()
        let code = app.otherElements.matching(NSPredicate(format: "label BEGINSWITH 'Code '")).firstMatch
        XCTAssertTrue(code.waitForExistence(timeout: 30), "the code screen never appeared")
        try code.label.filter(\.isNumber).write(to: directory.appending(path: "code.txt"), atomically: true, encoding: .utf8)
        XCTAssertTrue(app.staticTexts.matching(NSPredicate(format: "label BEGINSWITH 'Paired with'")).firstMatch
            .waitForExistence(timeout: 30), "the computer never confirmed")
        app.buttons["Done"].tap()
        try mark("paired")

        // The watch app must be open before it can be allowed.
        _ = try wait(for: directory.appending(path: "watch-open.txt"), timeout: 240)

        // The computer's page, and its Apple Watch section.
        let computer = app.staticTexts["e2e-host"].firstMatch
        XCTAssertTrue(computer.waitForExistence(timeout: 20))
        computer.tap()
        let allow = app.buttons["Allow Apple Watch"]
        XCTAssertTrue(allow.waitForExistence(timeout: 20), "no Apple Watch section on the computer's page")
        // The link to the watch can take a moment to come up.
        var allowed = false
        for attempt in 1...6 where !allowed {
            allow.tap()
            // Signing for the watch is behind Face ID; the script presents a face.
            try mark("watch-tapped-\(attempt)")
            allowed = app.buttons["Renew"].waitForExistence(timeout: 25)
        }
        if !allowed {
            try XCUIScreen.main.screenshot().pngRepresentation.write(to: directory.appending(path: "phone-after-allow.png"))
            XCTFail("the watch was never allowed")
            return
        }
        try mark("watch-allowed")

        // Stay open: the watch may hand its answers to this app to carry.
        _ = try? wait(for: directory.appending(path: "finished.txt"), timeout: 400)
    }
}
