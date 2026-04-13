import Foundation

// MARK: - Helper Entry Point
//
// This file is the executable entry point for the Phantom Privileged Helper.
// It is compiled as a separate command-line tool target (not the app target) and
// installed by launchd at:
//   /Library/PrivilegedHelperTools/com.woady.phantom.helper
//
// Lifecycle:
//   1. The main app calls SMJobBless() which asks launchd to install and start this helper.
//   2. The helper registers a Mach service and waits for XPC connections.
//   3. The app connects via NSXPCConnection and calls methods on SGPrivilegedHelperProtocol.
//   4. launchd keeps the helper alive; it exits when the XPC listener is invalidated.

let helper = PrivilegedHelperDelegate()
helper.run()
