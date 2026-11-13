// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: Apache-2.0

package com.satellion.passmcp.sdk;

/**
 * Client-side tool execution safety policy. Defaults to read-only ({@code allowMutations == false}),
 * refusing mutating and unannotated tools unless mutations are explicitly enabled.
 *
 * @param allowMutations whether tools without {@code readOnlyHint == true} may be called
 */
public record Policy(boolean allowMutations) {
    /**
     * Creates the default read-only execution policy ({@code allowMutations = false}).
     */
    public Policy() {
        this(false);
    }

    /**
     * Returns the strict read-only default policy.
     *
     * @return read-only {@link Policy}
     */
    public static Policy readOnly() {
        return new Policy(false);
    }

    /**
     * Returns a policy that permits mutating and unannotated tool calls.
     *
     * @return mutation-permitting {@link Policy}
     */
    public static Policy allowingMutations() {
        return new Policy(true);
    }

    /**
     * Reports whether {@code tool} may be invoked under this policy.
     *
     * @param tool candidate tool descriptor
     * @return {@code true} if {@code tool.readOnlyHint()} or {@code allowMutations} is {@code true}
     */
    public boolean allows(Tool tool) {
        if (tool == null) {
            return false;
        }
        return tool.readOnlyHint() || allowMutations;
    }

    /**
     * Enforces this policy on {@code tool}, throwing {@link SecurityException} when refused.
     *
     * @param tool candidate tool descriptor
     */
    public void enforce(Tool tool) {
        if (tool == null) {
            throw new SecurityException("Policy refused execution: unknown tool");
        }
        if (!allows(tool)) {
            throw new SecurityException(
                    "Policy refused execution of tool \"" + tool.name() + "\": readOnlyHint is not true");
        }
    }
}
