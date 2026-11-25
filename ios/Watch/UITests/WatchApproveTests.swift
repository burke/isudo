import XCTest

/// The watch's half of `ios/e2e-watch.sh`: a real request, approved on the
/// watch by holding the button, as a person would.
///
/// The script pairs a phone Simulator with a development build of isudo,
/// has the phone authorise this watch, turns the watch on for that
/// computer, and runs a command. This test only looks at the watch app and
/// presses what a person would press. Nothing in the app is switched off
/// for it. Without the script's directory in the environment it is skipped.
final class WatchApproveTests: XCTestCase {
    @MainActor
    func testApproveOnTheWatch() throws {
        guard let path = ProcessInfo.processInfo.environment["ISUDO_E2E_DIR"] else {
            throw XCTSkip("run through ios/e2e-watch.sh")
        }
        // Each step depends on the one before.
        continueAfterFailure = false
        let directory = URL(filePath: path)
        func mark(_ name: String) throws {
            try name.write(to: directory.appending(path: name + ".txt"), atomically: true, encoding: .utf8)
        }

        // Open on the wrist before the phone is asked to allow this watch:
        // the phone can only reach a watch whose app is running.
        let app = XCUIApplication()
        app.launch()
        XCTAssertTrue(app.staticTexts["Not set up"].waitForExistence(timeout: 30), "a fresh watch should say it is not set up")
        try mark("watch-open")

        // The phone authorises it, and the watch says which computer for.
        XCTAssertTrue(app.staticTexts["e2e-host"].waitForExistence(timeout: 240), "the watch was never authorised")
        try mark("watch-ready")

        // A request arrives. It is one this watch may approve.
        let approve = app.buttons["Approve"]
        XCTAssertTrue(approve.waitForExistence(timeout: 180), "no request the watch may approve appeared")
        let command = app.descendants(matching: .any).matching(NSPredicate(format: "label CONTAINS 'e2e-watch'")).firstMatch
        XCTAssertTrue(command.exists, "the argument is not on the watch's screen")
        if !approve.isHittable {
            app.swipeUp()
        }
        // A tap is not enough.
        approve.tap()
        XCTAssertFalse(app.staticTexts["Approved"].waitForExistence(timeout: 3), "a tap approved the request")
        approve.press(forDuration: 1.6)
        if !app.staticTexts["Approved"].waitForExistence(timeout: 30) {
            try XCUIScreen.main.screenshot().pngRepresentation.write(to: directory.appending(path: "watch-after-approve.png"))
            XCTFail("the watch never showed Approved")
            return
        }
        try mark("watch-approved")

        // A second request, with a variable named: only the phone may
        // approve it. The watch shows it and offers to deny.
        let review = app.staticTexts["Review on iPhone"]
        XCTAssertTrue(review.waitForExistence(timeout: 120), "the phone-only request never appeared")
        XCTAssertFalse(app.buttons["Approve"].exists, "the watch offered to approve a phone-only request")
        if !app.buttons["Deny"].isHittable {
            app.swipeUp()
        }
        app.buttons["Deny"].tap()
        let reason = app.buttons["Ask me on my phone"]
        XCTAssertTrue(reason.waitForExistence(timeout: 10))
        reason.tap()
        XCTAssertTrue(app.staticTexts["Denied"].waitForExistence(timeout: 30), "the watch never showed Denied")
        try mark("watch-denied")
    }
}
