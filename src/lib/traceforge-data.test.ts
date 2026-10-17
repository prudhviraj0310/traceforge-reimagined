import { describe, it, expect } from "vitest";
import { findAttackPath, blastRadius, buildInvestigation } from "./traceforge-data";

describe("seeded scenario", () => {
  it("finds the 5-hop path to the PCI vault", () => {
    const p = findAttackPath("wl-payment-ingress");
    expect(p.length - 1).toBe(5);
    expect(p[p.length - 1]).toBe("ds-customer-vault");
  });
  it("exposes 4.5M sensitive records", () => {
    expect(blastRadius("wl-payment-ingress").sensitiveRecords).toBe(4500000);
  });
});

describe("remediation cut", () => {
  it("cutting the choke point makes the PCI vault unreachable", () => {
    const { cut } = buildInvestigation("ALERT-2026-9812");
    expect(findAttackPath("wl-payment-ingress", cut)).not.toContain("ds-customer-vault");
    expect(blastRadius("wl-payment-ingress", cut).sensitiveRecords).toBe(0);
  });
  it("recalls prior incidents on the same workload", () => {
    const mem = [{ alertId: "ALERT-2026-9812", workload: "wl-payment-ingress", choke: "pol-legacy-payments", at: "" }];
    expect(buildInvestigation("ALERT-2026-9812", mem).events[0]!.step).toBe("MEMORY");
  });
});
