import XCTest

final class LaunchTests: XCTestCase {
    @MainActor
    func testEmptyStateInvitesPairing() {
        let app = XCUIApplication()
        app.launchArguments = ["-fixture", "empty"]
        app.launch()
        XCTAssertTrue(app.buttons["Pair a computer"].waitForExistence(timeout: 20))
    }
}

/// Saves screenshots of sample data, including parts of a card that are
/// below the fold. Run through `ios/screenshots.sh --scrolled DIR`.
final class ScreenshotTests: XCTestCase {
    @MainActor
    func testScrolledCards() throws {
        guard let path = ProcessInfo.processInfo.environment["ISUDO_SHOT_DIR"] else {
            throw XCTSkip("run through ios/screenshots.sh")
        }
        // The environment list, unfolded.
        do {
            let app = XCUIApplication()
            app.launchArguments = ["-fixture", "plain", "-appearance", "light"]
            app.launch()
            let disclosure = app.buttons.matching(NSPredicate(format: "label BEGINSWITH 'Environment'")).firstMatch
            XCTAssertTrue(disclosure.waitForExistence(timeout: 20))
            XCTAssertFalse(app.staticTexts["set by isudo"].firstMatch.exists, "the list starts folded")
            disclosure.tap()
            XCTAssertTrue(app.staticTexts["set by isudo"].firstMatch.waitForExistence(timeout: 5))
            app.swipeUp()
            Thread.sleep(forTimeInterval: 1)
            try XCUIScreen.main.screenshot().pngRepresentation
                .write(to: URL(filePath: path).appending(path: "environment-light.png"))
        }
        for (fixture, appearance) in [("risky", "light"), ("risky", "dark"), ("long", "dark"), ("multi", "light")] {
            let app = XCUIApplication()
            app.launchArguments = ["-fixture", fixture, "-appearance", appearance]
            app.launch()
            XCTAssertTrue(app.buttons["Deny"].firstMatch.waitForExistence(timeout: 20))
            if fixture == "long" {
                // Read the command to its end, which is what enables Approve.
                let command = app.scrollViews.matching(NSPredicate(format: "label BEGINSWITH 'Command'")).firstMatch
                for _ in 0..<12 where !app.buttons["Approve"].firstMatch.isEnabled { command.swipeUp() }
                XCTAssertTrue(app.buttons["Approve"].firstMatch.isEnabled, "reading to the end did not enable Approve")
            } else {
                app.swipeUp()
            }
            Thread.sleep(forTimeInterval: 1)
            let file = URL(filePath: path).appending(path: "\(fixture)-\(appearance)-scrolled.png")
            try XCUIScreen.main.screenshot().pngRepresentation.write(to: file)
        }
    }

    /// A long command cannot be approved until it has been read to the end.
    @MainActor
    func testLongCommandGatesApproval() {
        let app = XCUIApplication()
        app.launchArguments = ["-fixture", "long"]
        app.launch()
        let approve = app.buttons["Approve"].firstMatch
        XCTAssertTrue(approve.waitForExistence(timeout: 20))
        XCTAssertFalse(approve.isEnabled, "Approve was enabled before the command was read")
        // A short command needs no scrolling.
        app.terminate()
        app.launchArguments = ["-fixture", "plain"]
        app.launch()
        XCTAssertTrue(app.buttons["Approve"].firstMatch.waitForExistence(timeout: 20))
        XCTAssertTrue(app.buttons["Approve"].firstMatch.isEnabled)
    }
}

/// Drives the real app against a real relay and a real `isudo` process.
///
/// `ios/e2e.sh` runs the other half: it starts the relay and
/// `isudo-admin pair`, leaves the pairing link in a directory, and waits for
/// this test to leave the code there. The directory is passed in the
/// environment; without it the test is skipped.
///
/// The app is driven only through its interface. Nothing in the app is
/// switched off for the test.
final class EndToEndTests: XCTestCase {
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
    func testPairApproveDeny() throws {
        guard let path = ProcessInfo.processInfo.environment["ISUDO_E2E_DIR"] else {
            throw XCTSkip("run through ios/e2e.sh")
        }
        let directory = URL(filePath: path)
        let link = try wait(for: directory.appending(path: "link.txt"), timeout: 60)

        let app = XCUIApplication()
        app.launch()

        // Pair by pasting the link, as one must in the Simulator.
        XCTAssertTrue(app.buttons["Pair a computer"].waitForExistence(timeout: 30))
        app.buttons["Pair a computer"].firstMatch.tap()
        let paste = app.buttons["Paste a pairing link instead"]
        XCTAssertTrue(paste.waitForExistence(timeout: 10))
        paste.tap()
        let field = app.alerts.textFields.firstMatch
        XCTAssertTrue(field.waitForExistence(timeout: 10))
        field.typeText(link)
        app.alerts.buttons["Pair"].tap()

        // The code the person would read off the phone and type.
        let code = app.otherElements.matching(NSPredicate(format: "label BEGINSWITH 'Code '")).firstMatch
        XCTAssertTrue(code.waitForExistence(timeout: 30), "the code screen never appeared")
        let digits = code.label.filter(\.isNumber)
        XCTAssertEqual(digits.count, 6)
        try digits.write(to: directory.appending(path: "code.txt"), atomically: true, encoding: .utf8)

        XCTAssertTrue(app.staticTexts.matching(NSPredicate(format: "label BEGINSWITH 'Paired with'")).firstMatch
            .waitForExistence(timeout: 30), "the computer never confirmed")
        app.buttons["Done"].tap()
        try "paired".write(to: directory.appending(path: "paired.txt"), atomically: true, encoding: .utf8)

        // First request: approve.
        let approve = app.buttons["Approve"]
        XCTAssertTrue(approve.waitForExistence(timeout: 60), "no request card appeared")
        XCTAssertTrue(app.staticTexts["e2e-approved"].exists, "the argument is not on the card")
        approve.tap()
        // The script on the Mac now presents a matching face to the Simulator.
        try "tapped".write(to: directory.appending(path: "approve-tapped.txt"), atomically: true, encoding: .utf8)
        if !app.staticTexts["Approved"].waitForExistence(timeout: 20) {
            try XCUIScreen.main.screenshot().pngRepresentation.write(to: directory.appending(path: "after-approve.png"))
            XCTFail("the card never showed Approved")
            return
        }
        try "approved".write(to: directory.appending(path: "approved.txt"), atomically: true, encoding: .utf8)

        // Second request: deny with a reason.
        let deny = app.buttons["Deny"]
        XCTAssertTrue(app.staticTexts["e2e-denied"].waitForExistence(timeout: 60), "the second card never appeared")
        deny.tap()
        let reason = app.textFields["Reason (optional)"].firstMatch.exists
            ? app.textFields["Reason (optional)"].firstMatch : app.textViews.firstMatch
        XCTAssertTrue(reason.waitForExistence(timeout: 10))
        reason.typeText("use staging")
        app.navigationBars.buttons["Deny"].tap()
        try "tapped".write(to: directory.appending(path: "deny-tapped.txt"), atomically: true, encoding: .utf8)
        if !app.staticTexts["Denied"].waitForExistence(timeout: 20) {
            try XCUIScreen.main.screenshot().pngRepresentation.write(to: directory.appending(path: "after-deny.png"))
            XCTFail("the card never showed Denied")
            return
        }
        try "denied".write(to: directory.appending(path: "denied.txt"), atomically: true, encoding: .utf8)
    }
}
