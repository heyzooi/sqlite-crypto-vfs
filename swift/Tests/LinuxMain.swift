import XCTest

import SQLiteCryptoVFSTests

var tests = [XCTestCaseEntry]()
tests += SQLiteCryptoVFSTests.allTests()
XCTMain(tests)