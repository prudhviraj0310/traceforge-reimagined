import { describe, it, expect } from "vitest";
import { findAttackPath, blastRadius } from "./traceforge-data";

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
