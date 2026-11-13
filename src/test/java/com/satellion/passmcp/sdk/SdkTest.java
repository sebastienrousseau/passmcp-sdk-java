// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: Apache-2.0

package com.satellion.passmcp.sdk;

/**
 * Maven Surefire POJO test adapter so {@code mvn test} executes the full
 * zero-dependency conformance suite without requiring external test JARs.
 */
public final class SdkTest {
    /** Creates a new POJO test instance for Surefire. */
    public SdkTest() {
    }

    /**
     * Runs all SDK conformance suites via {@link SdkTestRunner}.
     *
     * @throws Exception if any check fails
     */
    public void testAllSuites() throws Exception {
        SdkTestRunner.runAll();
    }
}
